package backdoordetected.analyzers;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ParseResult;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.Parameter;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.*;
import com.github.javaparser.ast.stmt.ReturnStmt;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;
import com.github.javaparser.symbolsolver.JavaSymbolSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.CombinedTypeSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.JavaParserTypeSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.ReflectionTypeSolver;
import backdoordetected.cache.AnalysisCache;
import backdoordetected.cache.ASTCache;
import backdoordetected.cache.FileRiskClassifier;
import backdoordetected.detection.BukkitAPIKnowledge;
import backdoordetected.detection.PathCondition;
import backdoordetected.detection.SanitizerAnalyzer;
import backdoordetected.models.AnalysisResult;
import backdoordetected.utils.StandaloneLogger;
import java.io.IOException;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.*;
import java.util.logging.Logger;

public class DataFlowAnalyzer {

    private static final Logger logger = StandaloneLogger.getLogger();

    public DataFlowAnalyzer() {
    }

    private static final Map<String, String> DANGEROUS_SINKS = new HashMap<>();
    private static final Set<String> TAINT_SOURCES = new HashSet<>();
    private static final Set<String> CRYPTO_TAINT_PROPAGATORS = new HashSet<>();
    private static final Map<String, String> SANITIZERS = new HashMap<>();
    private static final Set<java.util.regex.Pattern> SANITIZER_PATTERNS = new HashSet<>();

    static {
        DANGEROUS_SINKS.put("dispatchCommand", "HIGH: Executes a command as the console");
        DANGEROUS_SINKS.put("exec", "CRITICAL: Executes system commands");
        DANGEROUS_SINKS.put("start", "CRITICAL: Starts a system process (ProcessBuilder)");
        DANGEROUS_SINKS.put("setOp", "CRITICAL: Grants OP status to a player");
        DANGEROUS_SINKS.put("lookup", "CRITICAL: JNDI lookup, potential for RCE via deserialization (e.g., Log4Shell)");
        DANGEROUS_SINKS.put("invoke", "CRITICAL: Reflection invoke, a common final step in gadget chains");
        DANGEROUS_SINKS.put("defineClass", "CRITICAL: Defines a class from bytes, can be used to load malicious code");
        DANGEROUS_SINKS.put("newTransformer", "CRITICAL: Can be used to create malicious XSLT transformers for RCE");
        TAINT_SOURCES.add("PlayerCommandPreprocessEvent.getMessage");
        TAINT_SOURCES.add("AsyncPlayerChatEvent.getMessage");
        TAINT_SOURCES.add("PlayerChatEvent.getMessage");
        TAINT_SOURCES.add("SignChangeEvent.getLine");
        TAINT_SOURCES.add("PlayerJoinEvent.getPlayer");
        TAINT_SOURCES.add("PlayerQuitEvent.getPlayer");
        TAINT_SOURCES.add("PlayerLoginEvent.getPlayer");
        TAINT_SOURCES.add("PlayerInteractEvent.getPlayer");
        TAINT_SOURCES.add("java.io.ObjectInputStream.readObject");
        TAINT_SOURCES.add("com.fasterxml.jackson.databind.ObjectMapper.readValue");
        TAINT_SOURCES.add("com.google.gson.Gson.fromJson");
        TAINT_SOURCES.add("org.yaml.snakeyaml.Yaml.load");
        CRYPTO_TAINT_PROPAGATORS.add("java.util.Base64$Decoder.decode");
        CRYPTO_TAINT_PROPAGATORS.add("javax.crypto.Cipher.doFinal");
        CRYPTO_TAINT_PROPAGATORS.add("decrypt");
        CRYPTO_TAINT_PROPAGATORS.add("deobfuscate");
        CRYPTO_TAINT_PROPAGATORS.add("decode");
        CRYPTO_TAINT_PROPAGATORS.add("xor");
        CRYPTO_TAINT_PROPAGATORS.add("customDecrypt");
        CRYPTO_TAINT_PROPAGATORS.add("decipher");
        SANITIZERS.put("Pattern.quote", "Regex escaping");
        SANITIZERS.put("StringEscapeUtils.escapeJava", "Java string escaping");
        SANITIZERS.put("StringEscapeUtils.escapeHtml", "HTML escaping");
        SANITIZERS.put("Integer.parseInt", "Type conversion to int");
        SANITIZERS.put("Long.parseLong", "Type conversion to long");
        SANITIZERS.put("Double.parseDouble", "Type conversion to double");
        SANITIZERS.put("Float.parseFloat", "Type conversion to float");
        SANITIZERS.put("Boolean.parseBoolean", "Type conversion to boolean");
        SANITIZERS.put("UUID.fromString", "UUID validation");
        SANITIZERS.put("Enum.valueOf", "Enum validation");

        SANITIZERS.put("equalsIgnoreCase", "String comparison");
        SANITIZERS.put("equals", "String comparison");
        SANITIZERS.put("startsWith", "Prefix validation");
        SANITIZERS.put("endsWith", "Suffix validation");
        SANITIZERS.put("contains", "Substring/Config check");
        SANITIZERS.put("isEmpty", "Empty check");
        SANITIZERS.put("isBlank", "Blank check");
        SANITIZERS.put("trim", "Whitespace removal");
        SANITIZERS.put("toLowerCase", "Case normalization");
        SANITIZERS.put("toUpperCase", "Case normalization");
        SANITIZERS.put("matches", "Regex validation");

        SANITIZERS.put("hasPermission", "Permission check");
        SANITIZERS.put("isOp", "OP status check");
        SANITIZERS.put("hasPlayedBefore", "Player validation");
        SANITIZERS.put("isOnline", "Player online check");
        SANITIZERS.put("isBanned", "Ban status check");
        SANITIZERS.put("isWhitelisted", "Whitelist check");

        SANITIZERS.put("isSet", "Config key validation");
        SANITIZER_PATTERNS.add(java.util.regex.Pattern.compile("replaceAll\\(\"\\[\\^[a-zA-Z0-9]+\\]\""));
        SANITIZER_PATTERNS.add(java.util.regex.Pattern.compile("matches\\(\"\\[a-zA-Z0-9\\]+\""));
    }

    public AnalysisResult analyze(List<Path> javaFiles, Path workingDirectory) {
        Map<String, List<String>> allFindings = new HashMap<>();
        List<Path> failedFiles = new ArrayList<>();

        Map<String, Set<Integer>> globalTaintedParameters = new HashMap<>();
        Set<String> taintPropagatingMethods = new HashSet<>();
        Path cacheFile = workingDirectory.resolve(".backdoor-cache").resolve("dataflow-cache.json");
        AnalysisCache cache;
        try {
            cache = AnalysisCache.load(cacheFile);
            logger.info("[DataFlow] Loaded analysis cache from: " + cacheFile);
        } catch (IOException e) {
            logger.warning("[DataFlow] Failed to load cache, starting fresh: " + e.getMessage());
            cache = new AnalysisCache();
        }
        List<Path> changedFiles = new ArrayList<>();
        List<Path> unchangedFiles = new ArrayList<>();

        for (Path file : javaFiles) {
            try {
                if (cache.isFileChanged(file, workingDirectory)) {
                    changedFiles.add(file);
                } else {
                    unchangedFiles.add(file);
                }
            } catch (IOException e) {
                changedFiles.add(file);
            }
        }

        logger.info(String.format("[DataFlow] Incremental Analysis: %d unchanged, %d changed files",
                unchangedFiles.size(), changedFiles.size()));

        FileRiskClassifier.Stats filterStats = new FileRiskClassifier.Stats();
        List<Path> filesToAnalyze = new ArrayList<>();

        for (Path file : changedFiles) {
            try {
                FileRiskClassifier.RiskLevel risk = FileRiskClassifier.classifyFile(file);
                filterStats.record(risk);
                if (risk != FileRiskClassifier.RiskLevel.SKIP) {
                    filesToAnalyze.add(file);
                }
            } catch (IOException e) {
                logger.warning("[DataFlow] Failed to classify " + file + ", analyzing anyway");
                filesToAnalyze.add(file);
                filterStats.record(FileRiskClassifier.RiskLevel.MEDIUM);
            }
        }

        logger.info("[DataFlow] " + filterStats.toString());

        for (Path file : unchangedFiles) {
            try {
                Optional<AnalysisCache.CachedResult> cached = cache.getCachedResult(file, workingDirectory);
                if (cached.isPresent()) {
                    String fileName = file.getFileName().toString();
                    allFindings.put(fileName, cached.get().findings());

                    cached.get().taintedParams()
                            .forEach((sig, indices) -> globalTaintedParameters.put(sig, new HashSet<>(indices)));
                }
            } catch (IOException e) {
                logger.warning("[DataFlow] Failed to load cached result for " + file + ": " + e.getMessage());
                changedFiles.add(file);
            }
        }

        CombinedTypeSolver localCombinedTypeSolver = new CombinedTypeSolver();
        localCombinedTypeSolver.add(new ReflectionTypeSolver());
        localCombinedTypeSolver.add(new JavaParserTypeSolver(workingDirectory));

        ParserConfiguration parserConfiguration = new ParserConfiguration()
                .setSymbolResolver(new JavaSymbolSolver(localCombinedTypeSolver));
        JavaParser parser = new JavaParser(parserConfiguration);
        Map<Path, CompilationUnit> parsedFiles = new HashMap<>();

        logger.info("[DataFlow] Starting Phase 1: Parsing and Initial Analysis...");
        int totalFiles = filesToAnalyze.size();
        long phase1StartTime = System.nanoTime();

        int numThreads = Math.min(Runtime.getRuntime().availableProcessors(), filesToAnalyze.size());
        boolean useParallel = numThreads > 1 && totalFiles > 10;

        if (useParallel) {
            logger.info(String.format("[DataFlow] Using parallel parsing with %d threads for %d files",
                    numThreads, totalFiles));
            parseFilesParallel(filesToAnalyze, parser, parsedFiles, failedFiles, taintPropagatingMethods,
                    phase1StartTime);
        } else {
            logger.info("[DataFlow] Using sequential parsing (small workload or single core)");
            parseFilesSequential(filesToAnalyze, parser, parsedFiles, failedFiles, taintPropagatingMethods,
                    phase1StartTime);
        }

        System.out.println();

        logger.info("[DataFlow] Parsed files count: " + parsedFiles.size());
        logger.info("\n[DataFlow] Starting Phase 2: Building Call Graph...");
        Map<String, Set<String>> callGraph = buildCallGraph(parsedFiles);
        logger.info("[DataFlow] Call graph built with " + callGraph.size() + " methods.");
        logger.info("\n[DataFlow] Starting Phase 3: Worklist-based Inter-procedural Analysis...");
        Queue<String> worklist = new LinkedList<>();
        Set<String> inWorklist = new HashSet<>();
        Map<String, Path> methodToFile = new HashMap<>();
        for (Map.Entry<Path, CompilationUnit> entry : parsedFiles.entrySet()) {
            Path file = entry.getKey();
            CompilationUnit cu = entry.getValue();
            cu.findAll(MethodDeclaration.class).forEach(method -> {
                String sig = resolveMethodSignatureStatic(method);
                if (sig != null) {
                    methodToFile.put(sig, file);
                }
            });
        }

        worklist.addAll(methodToFile.keySet());
        inWorklist.addAll(methodToFile.keySet());

        int iteration = 0;
        int maxIterations = 50;
        int totalProcessed = 0;

        while (!worklist.isEmpty() && iteration < maxIterations) {
            iteration++;
            int processedThisIteration = 0;
            int worklistSize = worklist.size();
            logger.info("[DataFlow] Iteration " + iteration + ", worklist size: " + worklistSize);
            Set<String> currentBatch = new HashSet<>();
            while (!worklist.isEmpty()) {
                currentBatch.add(worklist.poll());
            }
            inWorklist.clear();

            for (String methodSig : currentBatch) {
                Path file = methodToFile.get(methodSig);
                if (file == null)
                    continue;

                CompilationUnit cu = parsedFiles.get(file);
                if (cu == null)
                    continue;

                Optional<MethodDeclaration> methodOpt = cu.findAll(MethodDeclaration.class).stream()
                        .filter(m -> methodSig.equals(resolveMethodSignatureStatic(m)))
                        .findFirst();

                if (methodOpt.isEmpty())
                    continue;

                MethodDeclaration method = methodOpt.get();
                List<String> fileFindings = new ArrayList<>();

                TaintAnalysisVisitor visitor = new TaintAnalysisVisitor(
                        taintPropagatingMethods,
                        globalTaintedParameters);

                method.accept(visitor, fileFindings);

                Map<String, Set<Integer>> newTaints = visitor.getNewTaintedParameters();
                boolean methodChanged = false;

                for (Map.Entry<String, Set<Integer>> taintEntry : newTaints.entrySet()) {
                    String calledMethodSig = taintEntry.getKey();
                    Set<Integer> newIndices = taintEntry.getValue();

                    if (!globalTaintedParameters.containsKey(calledMethodSig)) {
                        globalTaintedParameters.put(calledMethodSig, new HashSet<>(newIndices));
                        methodChanged = true;
                        logger.fine("New tainted method: " + calledMethodSig);
                    } else {
                        Set<Integer> existingIndices = globalTaintedParameters.get(calledMethodSig);
                        if (existingIndices.addAll(newIndices)) {
                            methodChanged = true;
                            logger.fine("Updated tainted method: " + calledMethodSig);
                        }
                    }
                }

                if (methodChanged) {
                    Set<String> callers = callGraph.getOrDefault(methodSig, Collections.emptySet());
                    for (String caller : callers) {
                        if (!inWorklist.contains(caller)) {
                            worklist.add(caller);
                            inWorklist.add(caller);
                        }
                    }
                }

                if (!fileFindings.isEmpty()) {
                    allFindings.computeIfAbsent(file.getFileName().toString(), k -> new ArrayList<>())
                            .addAll(fileFindings);
                }

                processedThisIteration++;
                totalProcessed++;
            }

            logger.info("[DataFlow] Iteration " + iteration + " complete. Processed " + processedThisIteration
                    + " methods.");
        }

        if (iteration >= maxIterations) {
            logger.warning("[DataFlow] Reached max iterations (" + maxIterations + "). Analysis might be incomplete.");
        } else {
            logger.info("[DataFlow] Analysis converged after " + iteration + " iterations. Total methods processed: "
                    + totalProcessed);
        }

        logger.info("[DataFlow] Saving analysis cache...");
        for (Path file : changedFiles) {
            try {
                String fileName = file.getFileName().toString();
                List<String> findings = allFindings.getOrDefault(fileName, new ArrayList<>());

                Map<String, Set<Integer>> fileTaintedParams = new HashMap<>();
                for (Map.Entry<String, Set<Integer>> entry : globalTaintedParameters.entrySet()) {
                    fileTaintedParams.put(entry.getKey(), entry.getValue());
                }

                cache.cacheResult(file, workingDirectory, findings, fileTaintedParams);
            } catch (IOException e) {
                logger.warning("[DataFlow] Failed to cache result for " + file + ": " + e.getMessage());
            }
        }

        try {
            cache.save(cacheFile);
            logger.info("[DataFlow] Cache saved successfully to: " + cacheFile);
        } catch (IOException e) {
            logger.warning("[DataFlow] Failed to save cache: " + e.getMessage());
        }

        return new AnalysisResult(allFindings, failedFiles);
    }

    private Map<String, Set<String>> buildCallGraph(Map<Path, CompilationUnit> parsedFiles) {
        Map<String, Set<String>> callGraph = new HashMap<>();

        for (CompilationUnit cu : parsedFiles.values()) {
            for (MethodDeclaration method : cu.findAll(MethodDeclaration.class)) {
                String callerSig = resolveMethodSignatureStatic(method);
                if (callerSig == null)
                    continue;

                for (MethodCallExpr call : method.findAll(MethodCallExpr.class)) {
                    String calleeSig = resolveMethodSignatureStatic(call);
                    if (calleeSig != null) {
                        callGraph.computeIfAbsent(calleeSig, k -> new HashSet<>()).add(callerSig);
                    }
                }
            }
        }

        return callGraph;
    }

    private static String resolveMethodSignatureStatic(Node node) {
        try {
            if (node instanceof MethodCallExpr) {
                return ((MethodCallExpr) node).resolve().getQualifiedSignature();
            } else if (node instanceof MethodDeclaration) {
                return ((MethodDeclaration) node).resolve().getQualifiedSignature();
            }
        } catch (Exception e) {
            if (node instanceof MethodDeclaration) {
                MethodDeclaration method = (MethodDeclaration) node;
                return method.getNameAsString();
            } else if (node instanceof MethodCallExpr) {
                MethodCallExpr call = (MethodCallExpr) node;
                return call.getNameAsString();
            }
        }
        return null;
    }

    private void printProgress(String phase, int processed, int total, long startTime) {
        if (total == 0)
            return;
        int progress = (processed * 100) / total;

        if (processed % (Math.max(1, total / 20)) == 0 || processed == total) {
            long elapsedTimeNs = System.nanoTime() - startTime;
            String etaString = "";
            if (processed > 0 && elapsedTimeNs > 0) {
                double timePerFile = (double) elapsedTimeNs / processed;
                long remainingFiles = total - processed;
                long etaSeconds = (long) ((remainingFiles * timePerFile) / 1_000_000_000);
                etaString = String.format("ETA: ~%ds", etaSeconds);
            }
            System.out.printf("\r[DataFlow] %s: %d%% (%d/%d) %s", phase, progress, processed, total, etaString);
            if (processed == total) {
                System.out.println();
            }
        }
    }

    private void parseFilesSequential(List<Path> files, JavaParser parser,
            Map<Path, CompilationUnit> parsedFiles,
            List<Path> failedFiles,
            Set<String> taintPropagatingMethods,
            long startTime) {
        int processedCount = 0;
        int totalFiles = files.size();

        for (Path file : files) {
            try {
                ParseResult<CompilationUnit> parseResult = ASTCache.parse(parser, file);
                if (parseResult.isSuccessful()) {
                    CompilationUnit cu = parseResult.getResult().get();
                    parsedFiles.put(file, cu);
                    cu.accept(new TaintPropagatingMethodVisitor(taintPropagatingMethods), null);
                } else {
                    failedFiles.add(file);
                }
            } catch (IOException | RuntimeException e) {
                logger.warning("[DataFlow] Failed to parse " + file + ": " + e.getMessage());
                failedFiles.add(file);
            }
            processedCount++;
            printProgress("Parsing", processedCount, totalFiles, startTime);
        }
    }

    private void parseFilesParallel(List<Path> files, JavaParser parser,
            Map<Path, CompilationUnit> parsedFiles,
            List<Path> failedFiles,
            Set<String> taintPropagatingMethods,
            long startTime) {
        int numThreads = Math.min(Runtime.getRuntime().availableProcessors(), files.size());
        ExecutorService executor = Executors.newFixedThreadPool(numThreads);

        Map<Path, CompilationUnit> concurrentParsedFiles = new ConcurrentHashMap<>();
        List<Path> concurrentFailedFiles = Collections.synchronizedList(new ArrayList<>());
        Set<String> concurrentTaintMethods = Collections.synchronizedSet(new HashSet<>());

        List<Future<Void>> futures = new ArrayList<>();
        for (Path file : files) {
            futures.add(executor.submit(() -> {
                try {
                    ParseResult<CompilationUnit> parseResult = ASTCache.parse(parser, file);
                    if (parseResult.isSuccessful()) {
                        CompilationUnit cu = parseResult.getResult().get();
                        concurrentParsedFiles.put(file, cu);
                        cu.accept(new TaintPropagatingMethodVisitor(concurrentTaintMethods), null);
                    } else {
                        concurrentFailedFiles.add(file);
                    }
                } catch (IOException | RuntimeException e) {
                    logger.warning("[DataFlow] Failed to parse " + file + ": " + e.getMessage());
                    concurrentFailedFiles.add(file);
                }
                return null;
            }));
        }
        int completed = 0;
        for (Future<Void> future : futures) {
            try {
                future.get();
                completed++;
                printProgress("Parsing", completed, files.size(), startTime);
            } catch (InterruptedException | ExecutionException e) {
                logger.warning("[DataFlow] Parallel parsing error: " + e.getMessage());
            }
        }
        executor.shutdown();
        parsedFiles.putAll(concurrentParsedFiles);
        failedFiles.addAll(concurrentFailedFiles);
        taintPropagatingMethods.addAll(concurrentTaintMethods);
        ASTCache.logStats();
    }

    private static class TaintAnalysisVisitor extends VoidVisitorAdapter<List<String>> {
        private final Map<String, Set<TaintValue>> taintedVariables;
        private final Set<String> taintPropagatingMethods;
        private final Map<String, Set<Integer>> globalTaintedParameters;
        private final Map<String, Set<Integer>> newTaintedParameters = new HashMap<>();
        private final Map<Node, String> resolvedSignatureCache = new HashMap<>();
        private final AliasAnalyzer aliasAnalyzer = new AliasAnalyzer();
        private final FieldSensitiveState fieldSensitiveState = new FieldSensitiveState();
        private final Map<String, Set<TaintValue>> taintedCollections = new HashMap<>();
        private final Stack<PathCondition> pathConditions = new Stack<>();

        public TaintAnalysisVisitor(Set<String> taintPropagatingMethods,
                Map<String, Set<Integer>> globalTaintedParameters) {
            this.taintPropagatingMethods = taintPropagatingMethods;
            this.globalTaintedParameters = globalTaintedParameters;
            this.taintedVariables = new HashMap<>();
        }

        public Map<String, Set<Integer>> getNewTaintedParameters() {
            return newTaintedParameters;
        }

        @Override
        public void visit(CompilationUnit n, List<String> findings) {
            super.visit(n, findings);
        }

        @Override
        public void visit(com.github.javaparser.ast.body.ClassOrInterfaceDeclaration n, List<String> findings) {
            super.visit(n, findings);
        }

        @Override
        public void visit(MethodDeclaration n, List<String> findings) {
            this.taintedVariables.clear();
            this.taintedCollections.clear();
            this.aliasAnalyzer.clear();
            this.fieldSensitiveState.clear();

            for (Parameter param : n.getParameters()) {
                String paramType = param.getType().asString();
                TaintValue taintValue = null;
                if (paramType.contains("Event")) {
                    taintValue = new TaintValue("Event Parameter: " + paramType,
                            n.getRange().map(r -> r.begin.line).orElse(-1));
                } else if (paramType.equals("Player")) {
                    taintValue = new TaintValue("Player Parameter", n.getRange().map(r -> r.begin.line).orElse(-1));
                } else if (paramType.equals("String[]")) {
                    taintValue = new TaintValue("String[] Parameter", n.getRange().map(r -> r.begin.line).orElse(-1));
                }
                if (taintValue != null) {
                    taintedVariables.computeIfAbsent(param.getNameAsString(), k -> new HashSet<>()).add(taintValue);
                }
            }

            if (n.getNameAsString().equals("onCommand") && n.getType().asString().equals("boolean")) {
                if (n.getParameterByType("String[]").isPresent()) {
                    String paramName = n.getParameterByType("String[]").get().getNameAsString();
                    TaintValue taintValue = new TaintValue("onCommand args",
                            n.getRange().map(r -> r.begin.line).orElse(-1));
                    taintedVariables.computeIfAbsent(paramName, k -> new HashSet<>()).add(taintValue);
                }
            }

            String methodSignature = resolveMethodSignature(n);
            if (methodSignature != null && globalTaintedParameters.containsKey(methodSignature)) {
                Set<Integer> taintedIndices = globalTaintedParameters.get(methodSignature);
                for (int i = 0; i < n.getParameters().size(); i++) {
                    if (taintedIndices.contains(i)) {
                        String paramName = n.getParameter(i).getNameAsString();
                        TaintValue taintValue = new TaintValue("Inter-procedural: " + methodSignature,
                                n.getRange().map(r -> r.begin.line).orElse(-1));
                        taintedVariables.computeIfAbsent(paramName, k -> new HashSet<>()).add(taintValue);
                    }
                }
            }

            super.visit(n, findings);
        }

        @Override
        public void visit(VariableDeclarationExpr n, List<String> findings) {
            for (VariableDeclarator var : n.getVariables()) {
                Optional<Expression> optInitializer = var.getInitializer();
                if (optInitializer.isPresent()) {
                    Expression initializer = optInitializer.get();
                    String targetVar = var.getNameAsString();

                    if (initializer.isNameExpr()) {
                        String sourceVar = initializer.asNameExpr().getNameAsString();
                        aliasAnalyzer.addAlias(targetVar, sourceVar);
                    }

                    Set<TaintValue> taintSources = getTaintSources(initializer);
                    if (!taintSources.isEmpty()) {
                        taintedVariables.computeIfAbsent(targetVar, k -> new HashSet<>()).addAll(taintSources);
                    } else {
                        String varType = var.getType().asString();
                        if (varType.equals("Player") || varType.contains("Event")) {
                            if (initializer.isMethodCallExpr()) {
                                MethodCallExpr call = initializer.asMethodCallExpr();
                                if (call.getScope().isPresent()) {
                                    Set<TaintValue> scopeTaint = getTaintSources(call.getScope().get());
                                    if (!scopeTaint.isEmpty()) {
                                        taintedVariables.computeIfAbsent(targetVar, k -> new HashSet<>())
                                                .addAll(scopeTaint);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            super.visit(n, findings);
        }

        @Override
        public void visit(AssignExpr n, List<String> findings) {
            super.visit(n, findings);

            Expression target = n.getTarget();
            Expression value = n.getValue();

            if (target.isFieldAccessExpr()) {
                FieldAccessExpr fieldAccess = target.asFieldAccessExpr();
                String fieldName = fieldAccess.getNameAsString();
                Expression scope = fieldAccess.getScope();

                if (scope.isNameExpr()) {
                    String scopeVar = scope.asNameExpr().getNameAsString();
                    Set<TaintValue> valueTaint = getTaintSources(value);
                    if (!valueTaint.isEmpty()) {
                        fieldSensitiveState.taintField(scopeVar, fieldName, valueTaint);

                        for (String alias : aliasAnalyzer.getAliases(scopeVar)) {
                            fieldSensitiveState.taintField(alias, fieldName, valueTaint);
                        }
                    }
                }
            }

            else if (target.isNameExpr()) {
                String targetVar = target.asNameExpr().getNameAsString();

                if (value.isNameExpr()) {
                    String sourceVar = value.asNameExpr().getNameAsString();
                    aliasAnalyzer.addAlias(targetVar, sourceVar);
                }

                Set<TaintValue> valueTaint = getTaintSources(value);
                if (!valueTaint.isEmpty()) {
                    taintedVariables.computeIfAbsent(targetVar, k -> new HashSet<>()).addAll(valueTaint);
                }
            }
        }

        @Override
        public void visit(MethodCallExpr call, List<String> findings) {
            super.visit(call, findings);

            String methodName = call.getNameAsString();
            if (call.getScope().isPresent()) {
                Expression scope = call.getScope().get();
                String scopeType = resolveExpressionType(scope);

                if (scopeType != null && BukkitAPIKnowledge.isBukkitClass(scopeType)) {
                    if (BukkitAPIKnowledge.isSafeMethod(scopeType, methodName)) {
                        logger.fine("Skipping safe Bukkit method: " + scopeType + "." + methodName);
                        return;
                    }
                    if (BukkitAPIKnowledge.isTaintedMethod(scopeType, methodName)) {
                        logger.info("Detected tainted Bukkit method: " + scopeType + "." + methodName);
                    }
                }
            }
            if (methodName.equals("forName") && call.getArguments().size() >= 1) {
                if (isExpressionTainted(call.getArgument(0))) {
                    findings.add(String.format(
                            "CRITICAL REFLECTION: Class.forName() called with tainted class name at line %d. " +
                                    "This allows arbitrary class loading and is a common backdoor technique.",
                            call.getRange().map(r -> r.begin.line).orElse(-1)));
                }
            }
            if (methodName.equals("invoke") && call.getArguments().size() >= 2) {
                boolean taintedArgs = false;
                for (int i = 1; i < call.getArguments().size(); i++) {
                    if (isExpressionTainted(call.getArgument(i))) {
                        taintedArgs = true;
                        break;
                    }
                }

                if (taintedArgs) {
                    findings.add(String.format(
                            "CRITICAL REFLECTION: Method.invoke() called with tainted arguments at line %d. " +
                                    "This allows arbitrary method execution with user-controlled data.",
                            call.getRange().map(r -> r.begin.line).orElse(-1)));
                }
            }
            if (methodName.equals("newInstance") && call.getArguments().size() >= 1) {
                boolean taintedArgs = false;
                for (Expression arg : call.getArguments()) {
                    if (isExpressionTainted(arg)) {
                        taintedArgs = true;
                        break;
                    }
                }

                if (taintedArgs) {
                    findings.add(String.format(
                            "CRITICAL REFLECTION: Constructor.newInstance() called with tainted arguments at line %d. "
                                    +
                                    "This allows arbitrary object instantiation with user-controlled data.",
                            call.getRange().map(r -> r.begin.line).orElse(-1)));
                }
            }

            if ((methodName.equals("loadClass") || methodName.equals("defineClass")) &&
                    call.getArguments().size() >= 1) {
                if (isExpressionTainted(call.getArgument(0))) {
                    findings.add(String.format(
                            "CRITICAL REFLECTION: ClassLoader.%s() called with tainted data at line %d. " +
                                    "This allows arbitrary class loading/definition.",
                            methodName, call.getRange().map(r -> r.begin.line).orElse(-1)));
                }
            }

            if (call.getScope().isPresent()) {
                Expression scope = call.getScope().get();
                if (scope.isNameExpr()) {
                    String scopeVar = scope.asNameExpr().getNameAsString();

                    if (methodName.equals("add") || methodName.equals("put") || methodName.equals("addAll")) {

                        Set<TaintValue> argTaints = new HashSet<>();
                        for (Expression arg : call.getArguments()) {
                            argTaints.addAll(getTaintSources(arg));
                        }

                        if (!argTaints.isEmpty()) {
                            taintedCollections.computeIfAbsent(scopeVar, k -> new HashSet<>()).addAll(argTaints);

                            for (String alias : aliasAnalyzer.getAliases(scopeVar)) {
                                taintedCollections.computeIfAbsent(alias, k -> new HashSet<>()).addAll(argTaints);
                            }
                        }
                    } else if (methodName.equals("get") || methodName.equals("iterator")
                            || methodName.equals("toArray")) {

                    }
                }
            }
            if (DANGEROUS_SINKS.containsKey(methodName)) {
                if (call.getScope().isPresent() && isExpressionTainted(call.getScope().get())) {
                    if (!(methodName.equals("setOp") && isSafeSetOpCall(call))) {
                        Set<TaintValue> scopeTaint = getTaintSources(call.getScope().get());
                        boolean allSanitized = scopeTaint.stream().allMatch(TaintValue::isSanitized);
                        boolean allValidated = scopeTaint.stream().allMatch(this::isValidatedByPath);

                        boolean isLegitimate = isLegitimateCommandPattern(call, scopeTaint);

                        Optional<String> backdoorPattern = matchesKnownPattern(call);

                        if (!allSanitized && !allValidated && !isLegitimate) {
                            StringBuilder finding = new StringBuilder();

                            if (backdoorPattern.isPresent()) {
                                finding.append(String.format(
                                        "BACKDOOR PATTERN DETECTED: %s at line %d\n",
                                        backdoorPattern.get(),
                                        call.getRange().map(r -> r.begin.line).orElse(-1)));
                            } else {
                                finding.append(String.format(
                                        "CRITICAL DATA FLOW: Dangerous method '%s' called on tainted object at line %d\n",
                                        methodName, call.getRange().map(r -> r.begin.line).orElse(-1)));
                            }

                            findings.add(finding.toString().trim());
                        } else {
                            if (allSanitized) {
                                logger.fine("Skipping sanitized taint at dangerous sink: " + methodName);
                            }
                            if (allValidated) {
                                logger.fine("Skipping path-validated taint at dangerous sink: " + methodName);
                            }
                            if (isLegitimate) {
                                logger.fine("Skipping legitimate pattern at dangerous sink: " + methodName);
                            }
                        }
                    }
                }
                for (Expression arg : call.getArguments()) {
                    if (methodName.equals("setOp")) {
                        if (!isExpressionTainted(arg)) {
                            continue;
                        }
                    }

                    if (isExpressionTainted(arg)) {
                        Set<TaintValue> argTaint = getTaintSources(arg);
                        boolean allSanitized = argTaint.stream().allMatch(TaintValue::isSanitized);
                        boolean allValidated = argTaint.stream().allMatch(this::isValidatedByPath);

                        boolean isLegitimate = isLegitimateCommandPattern(call, argTaint);

                        Optional<String> backdoorPattern = matchesKnownPattern(call);

                        if (!allSanitized && !allValidated && !isLegitimate) {

                            StringBuilder finding = new StringBuilder();

                            if (backdoorPattern.isPresent()) {
                                finding.append(String.format(
                                        "BACKDOOR PATTERN DETECTED: %s at line %d\n",
                                        backdoorPattern.get(),
                                        call.getRange().map(r -> r.begin.line).orElse(-1)));
                            } else {
                                finding.append(String.format(
                                        "CRITICAL DATA FLOW: Tainted data passed to dangerous sink '%s' at line %d\n",
                                        methodName, call.getRange().map(r -> r.begin.line).orElse(-1)));
                            }

                            finding.append("  Taint Sources:\n");
                            for (TaintValue tv : argTaint) {
                                finding.append(String.format("    - [%s] %s (line %d)\n",
                                        tv.getCategory(), tv.getSource(), tv.getLineNumber()));
                            }

                            if (hasPermissionCheckNearby(call)) {
                                finding.append(
                                        "Note: Permission check detected but not sufficient to prevent this flow\n");
                            } else {
                                finding.append("Warning: No permission check detected\n");
                            }

                            findings.add(finding.toString().trim());
                        } else {
                            if (allSanitized) {
                                logger.fine("Skipping sanitized taint at dangerous sink: " + methodName);
                            }
                            if (allValidated) {
                                logger.fine("Skipping path-validated taint at dangerous sink: " + methodName);
                            }
                            if (isLegitimate) {
                                logger.fine("Skipping legitimate pattern at dangerous sink: " + methodName);
                            }
                        }
                    }
                }
            }

            for (int i = 0; i < call.getArguments().size(); i++) {
                if (isExpressionTainted(call.getArgument(i))) {
                    String targetSignature = resolveMethodSignature(call);
                    if (targetSignature != null) {
                        newTaintedParameters.computeIfAbsent(targetSignature, k -> new HashSet<>()).add(i);
                    }
                }
            }
        }

        @Override
        public void visit(com.github.javaparser.ast.stmt.IfStmt ifStmt, List<String> findings) {
            Expression condition = ifStmt.getCondition();
            PathCondition pathCond = extractPathCondition(condition);

            pathConditions.push(pathCond);
            ifStmt.getThenStmt().accept(this, findings);
            pathConditions.pop();
            if (ifStmt.getElseStmt().isPresent()) {
                pathConditions.push(pathCond.negate());
                ifStmt.getElseStmt().get().accept(this, findings);
                pathConditions.pop();
            }
        }

        private PathCondition extractPathCondition(Expression condition) {
            boolean negated = false;
            if (condition.isUnaryExpr() && condition.asUnaryExpr()
                    .getOperator() == com.github.javaparser.ast.expr.UnaryExpr.Operator.LOGICAL_COMPLEMENT) {
                negated = true;
                condition = condition.asUnaryExpr().getExpression();
            }
            if (condition.isMethodCallExpr()) {
                MethodCallExpr call = condition.asMethodCallExpr();
                if (call.getNameAsString().equals("matches") && call.getArguments().size() == 1) {
                    String variable = call.getScope().map(Expression::toString).orElse(null);
                    String regex = call.getArgument(0).toString().replace("\"", "");
                    return PathCondition.regexMatch(variable, regex, negated);
                }

                if (call.getNameAsString().equals("contains") && call.getArguments().size() == 1) {
                    String variable = call.getArgument(0).toString();
                    return PathCondition.whitelist(variable, negated);
                }

                if (call.getNameAsString().equals("length") && call.getArguments().isEmpty()) {
                    String variable = call.getScope().map(Expression::toString).orElse(null);
                    return PathCondition.lengthCheck(variable, "unknown", negated);
                }
            }

            if (condition.isBinaryExpr()) {
                com.github.javaparser.ast.expr.BinaryExpr binary = condition.asBinaryExpr();
                if (binary.getOperator() == com.github.javaparser.ast.expr.BinaryExpr.Operator.NOT_EQUALS) {
                    if (binary.getRight().isNullLiteralExpr()) {
                        String variable = binary.getLeft().toString();
                        return PathCondition.nullCheck(variable, negated);
                    }
                }
            }

            return PathCondition.none();
        }

        private boolean isValidatedByPath(TaintValue taint) {
            if (pathConditions.isEmpty()) {
                return false;
            }

            for (PathCondition cond : pathConditions) {
                if (cond.validates(taint.getSource())) {
                    return true;
                }
            }

            return false;
        }

        private boolean isSanitizer(String methodSignature, String methodName, MethodCallExpr call) {
            if (SANITIZERS.containsKey(methodSignature)) {
                logger.fine("Detected sanitizer: " + methodSignature);
                return true;
            }
            if (SANITIZERS.containsKey(methodName)) {
                logger.fine("Detected sanitizer: " + methodName);
                return true;
            }
            String callStr = call.toString();
            for (java.util.regex.Pattern pattern : SANITIZER_PATTERNS) {
                if (pattern.matcher(callStr).find()) {
                    logger.fine("Detected sanitizer pattern: " + callStr);
                    return true;
                }
            }

            return false;
        }

        private boolean isSafeSetOpCall(MethodCallExpr call) {
            if (call.getArguments().size() == 1) {
                Expression arg = call.getArgument(0);
                return arg.isBooleanLiteralExpr() && !arg.asBooleanLiteralExpr().getValue();
            }
            return false;
        }

        private Set<TaintValue> getTaintSources(Expression expr) {
            Set<TaintValue> result = new HashSet<>();
            if (expr == null) {
                return result;
            }

            if (expr.isNameExpr()) {
                String varName = expr.asNameExpr().getNameAsString();

                for (String alias : aliasAnalyzer.getAliases(varName)) {
                    result.addAll(taintedVariables.getOrDefault(alias, Collections.emptySet()));
                    result.addAll(taintedCollections.getOrDefault(alias, Collections.emptySet()));
                }
                return result;
            }

            if (expr.isFieldAccessExpr()) {
                FieldAccessExpr fieldAccess = expr.asFieldAccessExpr();
                String fieldName = fieldAccess.getNameAsString();
                Expression scope = fieldAccess.getScope();
                if (scope.isNameExpr()) {
                    String scopeVar = scope.asNameExpr().getNameAsString();

                    for (String alias : aliasAnalyzer.getAliases(scopeVar)) {
                        result.addAll(fieldSensitiveState.getFieldTaint(alias, fieldName));
                    }
                }
                return result;
            }

            if (expr.isMethodCallExpr()) {
                MethodCallExpr call = expr.asMethodCallExpr();
                String methodSignature = resolveMethodSignature(call);
                String methodName = call.getNameAsString();

                if (methodSignature == null) {
                    methodSignature = methodName;
                }

                if (isSanitizer(methodSignature, methodName, call)) {
                    Set<TaintValue> argTaints = new HashSet<>();
                    for (Expression arg : call.getArguments()) {
                        argTaints.addAll(getTaintSources(arg));
                    }
                    Set<TaintValue> sanitizedTaints = new HashSet<>();
                    for (TaintValue tv : argTaints) {
                        sanitizedTaints.add(tv.withSanitization(methodName));
                    }
                    return sanitizedTaints;
                }

                if (call.getScope().isPresent()) {
                    Expression scope = call.getScope().get();
                    if (scope.isNameExpr()) {
                        String scopeVar = scope.asNameExpr().getNameAsString();

                        if (taintedCollections.containsKey(scopeVar)) {
                            result.addAll(taintedCollections.get(scopeVar));
                        }
                        for (String alias : aliasAnalyzer.getAliases(scopeVar)) {
                            result.addAll(taintedCollections.getOrDefault(alias, Collections.emptySet()));
                        }
                        if (!result.isEmpty()) {
                            return result;
                        }
                    }
                }

                if (methodSignature != null) {
                    final String finalMethodSignature = methodSignature;
                    boolean isCryptoPropagator = CRYPTO_TAINT_PROPAGATORS.stream()
                            .anyMatch(sig -> finalMethodSignature.startsWith(sig));
                    if (isCryptoPropagator) {
                        for (Expression arg : call.getArguments()) {
                            result.addAll(getTaintSources(arg));
                        }
                        if (!result.isEmpty()) {
                            return result;
                        }
                    }
                }

                if (call.getScope().isPresent()) {
                    String scopeType = resolveExpressionType(call.getScope().get());
                    String callMethodName = call.getNameAsString();

                    if (scopeType != null && BukkitAPIKnowledge.isTaintedMethod(scopeType, callMethodName)) {
                        result.add(new TaintValue(
                                "Bukkit:" + scopeType + "." + callMethodName,
                                call.getRange().map(r -> r.begin.line).orElse(-1)));
                        return result;
                    }
                }

                if (call.getScope().isPresent()) {
                    Expression scope = call.getScope().get();
                    result.addAll(getTaintSources(scope));

                    if (scope.isNameExpr()) {
                        String scopeVar = scope.asNameExpr().getNameAsString();
                        for (String source : TAINT_SOURCES) {
                            String[] parts = source.split("\\.");
                            if (parts.length == 2) {
                                String methodName2 = parts[1];
                                if (taintedVariables.containsKey(scopeVar) && methodName.equals(methodName2)) {
                                    result.addAll(taintedVariables.get(scopeVar));
                                }
                            }
                        }
                    }
                }

                if (taintPropagatingMethods.contains(methodSignature)) {
                    TaintValue taintValue = new TaintValue("Taint-propagating method: " + methodSignature,
                            call.getRange().map(r -> r.begin.line).orElse(-1));
                    result.add(taintValue);
                }
                return result;
            }

            if (expr.isBinaryExpr()) {
                BinaryExpr binaryExpr = expr.asBinaryExpr();
                if (binaryExpr.getOperator() == BinaryExpr.Operator.PLUS) {
                    result.addAll(getTaintSources(binaryExpr.getLeft()));
                    result.addAll(getTaintSources(binaryExpr.getRight()));
                }
                return result;
            }

            if (expr.isCastExpr()) {
                return getTaintSources(expr.asCastExpr().getExpression());
            }
            if (expr.isEnclosedExpr()) {
                return getTaintSources(expr.asEnclosedExpr().getInner());
            }

            return result;
        }

        private boolean isExpressionTainted(Expression expr) {
            return !getTaintSources(expr).isEmpty();
        }

        private String resolveMethodSignature(Node node) {
            if (resolvedSignatureCache.containsKey(node)) {
                return resolvedSignatureCache.get(node);
            }
            try {
                if (node instanceof MethodCallExpr) {
                    String sig = ((MethodCallExpr) node).resolve().getQualifiedSignature();
                    resolvedSignatureCache.put(node, sig);
                    return sig;
                } else if (node instanceof MethodDeclaration) {
                    String sig = ((MethodDeclaration) node).resolve().getQualifiedSignature();
                    resolvedSignatureCache.put(node, sig);
                    return sig;
                }
            } catch (Exception e) {

            }
            return null;
        }

        private String resolveExpressionType(Expression expr) {
            try {
                return expr.calculateResolvedType().describe();
            } catch (Exception e) {
                if (expr.isNameExpr()) {
                    String varName = expr.asNameExpr().getNameAsString();
                    return null;
                } else if (expr.isFieldAccessExpr()) {
                    return null;
                } else if (expr.isMethodCallExpr()) {
                    MethodCallExpr methodCall = expr.asMethodCallExpr();
                    try {
                        return methodCall.resolve().getReturnType().describe();
                    } catch (Exception ex) {
                        return null;
                    }
                }
                return null;
            }
        }

        private boolean hasPermissionCheckNearby(MethodCallExpr dangerousCall) {
            Optional<MethodDeclaration> methodOpt = dangerousCall.findAncestor(MethodDeclaration.class);
            if (methodOpt.isEmpty())
                return false;

            MethodDeclaration method = methodOpt.get();

            List<MethodCallExpr> permissionChecks = method.findAll(MethodCallExpr.class).stream()
                    .filter(call -> {
                        String name = call.getNameAsString();
                        return name.equals("hasPermission") ||
                                name.equals("isOp") ||
                                name.equals("hasPermissionNode") ||
                                name.equals("checkPermission");
                    })
                    .collect(java.util.stream.Collectors.toList());

            if (permissionChecks.isEmpty())
                return false;

            int dangerousLine = dangerousCall.getRange().map(r -> r.begin.line).orElse(-1);

            for (MethodCallExpr permCheck : permissionChecks) {
                int permLine = permCheck.getRange().map(r -> r.begin.line).orElse(-1);
                if (permLine > 0 && permLine < dangerousLine) {

                    Optional<com.github.javaparser.ast.stmt.IfStmt> ifStmt = permCheck
                            .findAncestor(com.github.javaparser.ast.stmt.IfStmt.class);

                    if (ifStmt.isPresent()) {

                        if (ifStmt.get().getThenStmt().containsWithinRange(dangerousCall)) {
                            logger.info("Permission check detected guarding dangerous call at line " + dangerousLine);
                            return true;
                        }
                    }
                }
            }

            return false;
        }

        private boolean isLegitimateCommandPattern(MethodCallExpr call, Set<TaintValue> taintSources) {
            String methodName = call.getNameAsString();

            if (methodName.equals("dispatchCommand") || methodName.equals("exec")) {
                if (hasPermissionCheckNearby(call)) {
                    logger.fine("Legitimate pattern: Permission-guarded command");
                    return true;
                }
            }

            for (TaintValue tv : taintSources) {
                TaintCategory category = tv.getCategory();
                if (category == TaintCategory.CONFIG) {
                    logger.fine("Legitimate pattern: Config-based command");
                    return true;
                }
            }

            if (call.getArguments().size() > 0) {
                Expression arg = call.getArgument(0);

                if (arg.isStringLiteralExpr()) {
                    logger.fine("Legitimate pattern: Hardcoded command");
                    return true;
                }

                if (arg.isBinaryExpr()) {
                    BinaryExpr binary = arg.asBinaryExpr();
                    if (binary.getOperator() == BinaryExpr.Operator.PLUS) {
                        if (binary.getLeft().isStringLiteralExpr()) {
                            String literal = binary.getLeft().asStringLiteralExpr().getValue();

                            if (literal.startsWith("/") || literal.matches("^[a-z]+:.*")) {
                                logger.fine("Legitimate pattern: Safe command prefix");
                                return true;
                            }
                        }
                    }
                }
            }

            return false;
        }

        private boolean containsBase64(Expression expr) {
            String exprStr = expr.toString();
            return exprStr.contains("Base64") &&
                    (exprStr.contains("decode") || exprStr.contains("encode"));
        }

        private boolean containsObfuscation(Expression expr) {
            String exprStr = expr.toString();

            if (exprStr.contains("^") && exprStr.contains("0x")) {
                return true;
            }

            if (exprStr.contains("byte[]") && exprStr.contains("new byte")) {
                return true;
            }

            if (exprStr.matches(".*\\(char\\).*\\+.*")) {
                return true;
            }

            return false;
        }

        private boolean hasObfuscatedArgument(MethodCallExpr call) {
            return call.getArguments().stream()
                    .anyMatch(arg -> containsBase64(arg) || containsObfuscation(arg));
        }

        private Optional<String> matchesKnownPattern(MethodCallExpr call) {
            String methodName = call.getNameAsString();

            if (methodName.equals("dispatchCommand") || methodName.equals("exec")) {
                if (hasObfuscatedArgument(call)) {
                    return Optional.of("Hidden Admin Command (Base64/Obfuscated)");
                }
            }

            if (methodName.equals("forName") || methodName.equals("invoke") ||
                    methodName.equals("newInstance")) {
                if (hasObfuscatedArgument(call)) {
                    return Optional.of("Reflection Execution Chain");
                }
            }

            if (methodName.equals("exec")) {
                Optional<MethodDeclaration> methodOpt = call.findAncestor(MethodDeclaration.class);
                if (methodOpt.isPresent()) {
                    MethodDeclaration method = methodOpt.get();
                    boolean hasNetworkOps = method.findAll(MethodCallExpr.class).stream()
                            .anyMatch(c -> {
                                String name = c.getNameAsString();
                                return name.contains("Socket") || name.contains("URL") ||
                                        name.contains("HttpURLConnection");
                            });

                    if (hasNetworkOps) {
                        return Optional.of("Network Backdoor");
                    }
                }
            }

            return Optional.empty();
        }
    }

    private enum TaintCategory {
        PLAYER_INPUT,
        DESERIALIZATION,
        NETWORK_INPUT,
        FILE_INPUT,
        CONFIG,
        DATABASE,
        UNKNOWN
    }

    private static class TaintValue {

        private final String source;
        private final int lineNumber;
        private final boolean sanitized;
        private final String sanitizer;
        private final PathCondition condition;
        private final TaintCategory category;

        public TaintValue(String source, int lineNumber) {
            this(source, lineNumber, false, null, PathCondition.none());
        }

        public TaintValue(String source, int lineNumber, boolean sanitized, String sanitizer) {
            this(source, lineNumber, sanitized, sanitizer, PathCondition.none());
        }

        public TaintValue(String source, int lineNumber, boolean sanitized, String sanitizer, PathCondition condition) {
            this.source = source;
            this.lineNumber = lineNumber;
            this.sanitized = sanitized;
            this.sanitizer = sanitizer;
            this.condition = condition != null ? condition : PathCondition.none();
            this.category = categorizeSource(source);
        }

        private static TaintCategory categorizeSource(String source) {
            if (source == null)
                return TaintCategory.UNKNOWN;

            String lowerSource = source.toLowerCase();

            if (lowerSource.contains("playercommand") || lowerSource.contains("playerchat") ||
                    lowerSource.contains("signevent") || lowerSource.contains("playerjoin") ||
                    lowerSource.contains("playerinteract")) {
                return TaintCategory.PLAYER_INPUT;
            }

            if (lowerSource.contains("readobject") || lowerSource.contains("fromjson") ||
                    lowerSource.contains("yaml.load") || lowerSource.contains("deserialize") ||
                    lowerSource.contains("objectmapper")) {
                return TaintCategory.DESERIALIZATION;
            }

            if (lowerSource.contains("getconfig") || lowerSource.contains("config.yml") ||
                    lowerSource.contains("configurationsection") || lowerSource.contains("config.get")) {
                return TaintCategory.CONFIG;
            }

            if (lowerSource.contains("socket") || lowerSource.contains("url") ||
                    lowerSource.contains("httpurlconnection") || lowerSource.contains("inputstream") ||
                    lowerSource.contains("network")) {
                return TaintCategory.NETWORK_INPUT;
            }

            if (lowerSource.contains("fileinputstream") || lowerSource.contains("bufferedreader") ||
                    lowerSource.contains("file.read") || lowerSource.contains("files.read")) {
                return TaintCategory.FILE_INPUT;
            }

            if (lowerSource.contains("resultset") || lowerSource.contains("preparedstatement") ||
                    lowerSource.contains("query") || lowerSource.contains("database")) {
                return TaintCategory.DATABASE;
            }

            return TaintCategory.UNKNOWN;
        }

        public String getSource() {
            return source;
        }

        public int getLineNumber() {
            return lineNumber;
        }

        public boolean isSanitized() {
            return sanitized;
        }

        public String getSanitizer() {
            return sanitizer;
        }

        public PathCondition getCondition() {
            return condition;
        }

        public TaintCategory getCategory() {
            return category;
        }

        public TaintValue withSanitization(String sanitizerName) {
            return new TaintValue(source, lineNumber, true, sanitizerName, condition);
        }

        public TaintValue withCondition(PathCondition newCondition) {
            return new TaintValue(source, lineNumber, sanitized, sanitizer, newCondition);
        }

        @Override
        public boolean equals(Object o) {
            if (this == o)
                return true;
            if (o == null || getClass() != o.getClass())
                return false;
            TaintValue that = (TaintValue) o;
            return lineNumber == that.lineNumber && sanitized == that.sanitized
                    && Objects.equals(source, that.source) && Objects.equals(sanitizer, that.sanitizer);
        }

        @Override
        public int hashCode() {
            return Objects.hash(source, lineNumber, sanitized, sanitizer);
        }

        @Override
        public String toString() {
            if (sanitized) {
                return source + " (line " + lineNumber + ", sanitized by " + sanitizer + ")";
            }
            return source + " (line " + lineNumber + ")";
        }
    }

    private static class AliasAnalyzer {
        private final Map<String, Integer> variableToAliasId = new HashMap<>();
        private final Map<Integer, Set<String>> aliasIdToVariables = new HashMap<>();

        private final Map<String, Set<String>> pointsToSet = new HashMap<>();
        private int nextAliasId = 0;

        public void clear() {
            variableToAliasId.clear();
            aliasIdToVariables.clear();
            pointsToSet.clear();
            nextAliasId = 0;
        }

        public void addAlias(String var1, String var2) {
            Integer aliasId1 = variableToAliasId.get(var1);
            Integer aliasId2 = variableToAliasId.get(var2);

            if (aliasId1 == null && aliasId2 == null) {
                int newId = nextAliasId++;
                Set<String> aliasSet = new HashSet<>();
                aliasSet.add(var1);
                aliasSet.add(var2);
                aliasIdToVariables.put(newId, aliasSet);
                variableToAliasId.put(var1, newId);
                variableToAliasId.put(var2, newId);
            } else if (aliasId1 == null) {
                aliasIdToVariables.get(aliasId2).add(var1);
                variableToAliasId.put(var1, aliasId2);
            } else if (aliasId2 == null) {
                aliasIdToVariables.get(aliasId1).add(var2);
                variableToAliasId.put(var2, aliasId1);
            } else if (!aliasId1.equals(aliasId2)) {
                Set<String> set1 = aliasIdToVariables.get(aliasId1);
                Set<String> set2 = aliasIdToVariables.get(aliasId2);
                set1.addAll(set2);
                for (String var : set2) {
                    variableToAliasId.put(var, aliasId1);
                }
                aliasIdToVariables.remove(aliasId2);
            }

            pointsToSet.computeIfAbsent(var1, k -> new HashSet<>()).add(var2);
            pointsToSet.computeIfAbsent(var2, k -> new HashSet<>()).add(var1);
        }

        public Set<String> getAliases(String var) {
            Integer aliasId = variableToAliasId.get(var);
            if (aliasId == null) {
                return Collections.singleton(var);
            }
            return aliasIdToVariables.get(aliasId);
        }

        public Set<String> getPointsToSet(String var) {
            return pointsToSet.getOrDefault(var, Collections.emptySet());
        }
    }

    private static class FieldSensitiveState {

        private final Map<String, Map<String, Set<TaintValue>>> objectFields = new HashMap<>();

        public void clear() {
            objectFields.clear();
        }

        public void taintField(String objectName, String fieldName, TaintValue taintValue) {
            objectFields.computeIfAbsent(objectName, k -> new HashMap<>())
                    .computeIfAbsent(fieldName, k -> new HashSet<>())
                    .add(taintValue);
        }

        public void taintField(String objectName, String fieldName, Set<TaintValue> taintValues) {
            objectFields.computeIfAbsent(objectName, k -> new HashMap<>())
                    .computeIfAbsent(fieldName, k -> new HashSet<>())
                    .addAll(taintValues);
        }

        public Set<TaintValue> getFieldTaint(String objectName, String fieldName) {
            return objectFields.getOrDefault(objectName, Collections.emptyMap())
                    .getOrDefault(fieldName, Collections.emptySet());
        }

        public boolean isFieldTainted(String objectName, String fieldName) {
            return !getFieldTaint(objectName, fieldName).isEmpty();
        }
    }

    private static class TaintPropagatingMethodVisitor extends VoidVisitorAdapter<Void> {
        private final Set<String> taintPropagatingMethods;
        private final TaintAnalysisVisitor internalTaintVisitor;

        public TaintPropagatingMethodVisitor(Set<String> taintPropagatingMethods) {
            this.taintPropagatingMethods = taintPropagatingMethods;

            this.internalTaintVisitor = new TaintAnalysisVisitor(Collections.emptySet(), Collections.emptyMap());
        }

        @Override
        public void visit(MethodDeclaration n, Void arg) {
            internalTaintVisitor.visit(n, new ArrayList<>());

            List<ReturnStmt> returnStmts = n.findAll(ReturnStmt.class);
            for (ReturnStmt returnStmt : returnStmts) {
                Optional<Expression> optExpr = returnStmt.getExpression();
                if (optExpr.isPresent()) {
                    Expression expr = optExpr.get();
                    if (internalTaintVisitor.isExpressionTainted(expr)) {
                        String signature = internalTaintVisitor.resolveMethodSignature(n);
                        if (signature != null) {
                            taintPropagatingMethods.add(signature);
                        } else {
                            taintPropagatingMethods.add(n.getNameAsString());
                        }
                        return;
                    }
                }
            }
        }
    }

    public record AnalysisResult(Map<String, List<String>> findings, List<Path> failedFiles) {
    }
}
