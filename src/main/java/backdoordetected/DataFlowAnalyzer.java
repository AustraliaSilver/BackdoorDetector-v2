package backdoordetected;

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

import java.io.IOException;
import java.nio.file.Path;
import java.util.*;
import java.util.logging.Logger;

public class DataFlowAnalyzer {

    private static final Logger logger = StandaloneLogger.getLogger();

    public DataFlowAnalyzer() {
    }

    private static final Map<String, String> DANGEROUS_SINKS = new HashMap<>();
    private static final Set<String> TAINT_SOURCES = new HashSet<>();
    private static final Set<String> CRYPTO_TAINT_PROPAGATORS = new HashSet<>();

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
    }

    public AnalysisResult analyze(List<Path> javaFiles, Path workingDirectory) {
        Map<String, List<String>> allFindings = new HashMap<>();
        List<Path> failedFiles = new ArrayList<>();

        
        Map<String, Set<Integer>> globalTaintedParameters = new HashMap<>();
        Set<String> taintPropagatingMethods = new HashSet<>();

        CombinedTypeSolver localCombinedTypeSolver = new CombinedTypeSolver();
        localCombinedTypeSolver.add(new ReflectionTypeSolver());
        localCombinedTypeSolver.add(new JavaParserTypeSolver(workingDirectory));

        ParserConfiguration parserConfiguration = new ParserConfiguration()
                .setSymbolResolver(new JavaSymbolSolver(localCombinedTypeSolver));
        JavaParser parser = new JavaParser(parserConfiguration);
        Map<Path, CompilationUnit> parsedFiles = new HashMap<>();

        logger.info("[DataFlow] Starting Phase 1: Parsing and Initial Analysis...");
        int totalFiles = javaFiles.size();
        long phase1StartTime = System.nanoTime();
        int processedCount1 = 0;

        for (Path file : javaFiles) {
            try {
                ParseResult<CompilationUnit> parseResult = parser.parse(file);
                if (parseResult.isSuccessful()) {
                    CompilationUnit cu = parseResult.getResult().get();
                    parsedFiles.put(file, cu);
                    
                    
                    cu.accept(new TaintPropagatingMethodVisitor(taintPropagatingMethods), null);
                } else {
                    failedFiles.add(file);
                }
            } catch (IOException | RuntimeException e) {
                
            }
            processedCount1++;
            printProgress("Parsing", processedCount1, totalFiles, phase1StartTime);
        }
        if (totalFiles > 0 && processedCount1 == totalFiles) {
            System.out.println();
        }

        logger.info("[DataFlow] Parsed files count: " + parsedFiles.size());
        logger.info("\n[DataFlow] Starting Phase 2: Fix-point Inter-procedural Analysis...");
        boolean changed;
        int iteration = 0;
        int maxIterations = 50; 

        do {
            iteration++;
            changed = false;
            logger.info("[DataFlow] Iteration " + iteration + "...");

            
            allFindings.clear();

            for (Map.Entry<Path, CompilationUnit> entry : parsedFiles.entrySet()) {
                Path file = entry.getKey();
                CompilationUnit cu = entry.getValue();
                List<String> fileFindings = new ArrayList<>();

                TaintAnalysisVisitor visitor = new TaintAnalysisVisitor(
                        taintPropagatingMethods,
                        globalTaintedParameters);

                logger.info("DEBUG: Analyzing file " + file);
                cu.accept(visitor, fileFindings);

                
                Map<String, Set<Integer>> newTaints = visitor.getNewTaintedParameters();
                for (Map.Entry<String, Set<Integer>> taintEntry : newTaints.entrySet()) {
                    String methodSig = taintEntry.getKey();
                    Set<Integer> newIndices = taintEntry.getValue();

                    if (!globalTaintedParameters.containsKey(methodSig)) {
                        globalTaintedParameters.put(methodSig, new HashSet<>(newIndices));
                        changed = true;
                        logger.fine("New tainted method detected: " + methodSig + " params: " + newIndices);
                    } else {
                        Set<Integer> existingIndices = globalTaintedParameters.get(methodSig);
                        if (existingIndices.addAll(newIndices)) {
                            changed = true;
                            logger.fine("Updated tainted method: " + methodSig + " params: " + existingIndices);
                        }
                    }
                }

                if (!fileFindings.isEmpty()) {
                    allFindings.put(file.getFileName().toString(), fileFindings);
                }
            }

        } while (changed && iteration < maxIterations);

        if (iteration >= maxIterations) {
            logger.warning("[DataFlow] Reached max iterations (" + maxIterations + "). Analysis might be incomplete.");
        } else {
            logger.info("[DataFlow] Analysis converged after " + iteration + " iterations.");
        }

        return new AnalysisResult(allFindings, failedFiles);
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

    private static class TaintAnalysisVisitor extends VoidVisitorAdapter<List<String>> {
        private final Map<String, Set<TaintValue>> taintedVariables; 
        private final Set<String> taintPropagatingMethods;
        private final Map<String, Set<Integer>> globalTaintedParameters;
        private final Map<String, Set<Integer>> newTaintedParameters = new HashMap<>();

        private final Map<Node, String> resolvedSignatureCache = new HashMap<>();

        
        private final AliasAnalyzer aliasAnalyzer = new AliasAnalyzer();

        
        private final FieldSensitiveState fieldSensitiveState = new FieldSensitiveState();

        
        private final Map<String, Set<TaintValue>> taintedCollections = new HashMap<>();

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
            logger.info("DEBUG: Visiting CompilationUnit");
            super.visit(n, findings);
        }

        @Override
        public void visit(com.github.javaparser.ast.body.ClassOrInterfaceDeclaration n, List<String> findings) {
            logger.info("DEBUG: Visiting class " + n.getNameAsString());
            super.visit(n, findings);
        }

        @Override
        public void visit(MethodDeclaration n, List<String> findings) {
            this.taintedVariables.clear();
            this.taintedCollections.clear();
            this.aliasAnalyzer.clear();
            this.fieldSensitiveState.clear();

            logger.info("DEBUG: Visiting method " + n.getNameAsString());

            
            for (Parameter param : n.getParameters()) {
                String paramType = param.getType().asString();
                logger.info("DEBUG: Param " + param.getNameAsString() + " type: " + paramType);
                TaintValue taintValue = null;
                if (paramType.contains("Event")) {
                    taintValue = new TaintValue("Event Parameter: " + paramType,
                            n.getRange().map(r -> r.begin.line).orElse(-1));
                    logger.info("DEBUG: Tainted param: " + param.getNameAsString());
                } else if (paramType.equals("Player")) {
                    taintValue = new TaintValue("Player Parameter", n.getRange().map(r -> r.begin.line).orElse(-1));
                    logger.info("DEBUG: Tainted param: " + param.getNameAsString());
                } else if (paramType.equals("String[]")) {
                    taintValue = new TaintValue("String[] Parameter", n.getRange().map(r -> r.begin.line).orElse(-1));
                    logger.info("DEBUG: Tainted param: " + param.getNameAsString());
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
                        String finding = String.format(
                                "CRITICAL DATA FLOW: Dangerous method '%s' called on tainted object at line %d.",
                                methodName, call.getRange().map(r -> r.begin.line).orElse(-1));
                        findings.add(finding);
                    }
                }
                for (Expression arg : call.getArguments()) {
                    if (methodName.equals("setOp")) {
                        if (!isExpressionTainted(arg)) {
                            continue;
                        }
                    }

                    if (isExpressionTainted(arg)) {
                        String finding = String.format(
                                "CRITICAL DATA FLOW: Tainted data passed to dangerous sink '%s' at line %d.",
                                call, call.getRange().map(r -> r.begin.line).orElse(-1));
                        findings.add(finding);
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
    }

    

    

    private static class TaintValue {

        private final String source;
        private final int lineNumber;

        public TaintValue(String source, int lineNumber) {
            this.source = source;
            this.lineNumber = lineNumber;
        }

        public String getSource() {
            return source;
        }

        public int getLineNumber() {
            return lineNumber;
        }

        @Override

        public boolean equals(Object o) {
            if (this == o)
                return true;
            if (o == null || getClass() != o.getClass())
                return false;
            TaintValue that = (TaintValue) o;
            return lineNumber == that.lineNumber && Objects.equals(source, that.source);
        }

        @Override
        public int hashCode() {
            return Objects.hash(source, lineNumber);
        }

        @Override
        public String toString() {
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
