package backdoordetected;
import com.github.javaparser.JavaParser;
import com.github.javaparser.ParseResult;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.body.Parameter;
import com.github.javaparser.ast.expr.*;
import com.github.javaparser.ast.stmt.ReturnStmt;
import com.github.javaparser.ast.nodeTypes.NodeWithOptionalScope;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;
import com.github.javaparser.resolution.declarations.ResolvedMethodDeclaration;
import com.github.javaparser.symbolsolver.resolution.typesolvers.CombinedTypeSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.JavaParserTypeSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.ReflectionTypeSolver;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.logging.Logger;
import com.github.javaparser.symbolsolver.JavaSymbolSolver;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;

public class DataFlowAnalyzer {

    private static final Logger logger = StandaloneLogger.getLogger();
    public DataFlowAnalyzer() {
    }

    private static final Map<String, String> DANGEROUS_SINKS = new HashMap<>();
    private static final Set<String> TAINT_SOURCES = new HashSet<>();

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
    }

    private static final Set<String> CRYPTO_TAINT_PROPAGATORS = Set.of(
        "javax.crypto.Cipher.doFinal",
        "javax.crypto.Cipher.update",
        "java.security.MessageDigest.digest"
    );
    
    private final SymbolicExecutor symbolicExecutor = new SymbolicExecutor();

    public AnalysisResult analyze(List<Path> javaFiles, Path workingDirectory) {
        Map<String, List<String>> allFindings = new HashMap<>();
        List<Path> failedFiles = new ArrayList<>();
        Set<String> taintPropagatingMethods = new HashSet<>();

        CombinedTypeSolver localCombinedTypeSolver = new CombinedTypeSolver();
        localCombinedTypeSolver.add(new ReflectionTypeSolver());
        localCombinedTypeSolver.add(new JavaParserTypeSolver(workingDirectory));
        
        ParserConfiguration parserConfiguration = new ParserConfiguration().setSymbolResolver(new JavaSymbolSolver(localCombinedTypeSolver));
        JavaParser parser = new JavaParser(parserConfiguration);
        Map<Path, CompilationUnit> parsedFiles = new HashMap<>();

        logger.info("[DataFlow] Starting Phase 1/2: Building taint propagation map...");
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
            } catch (IOException | RuntimeException e) { }
            processedCount1++;
            printProgress("Phase 1", processedCount1, totalFiles, phase1StartTime);
        }
        if (totalFiles > 0 && processedCount1 == totalFiles) {
            System.out.println();
        }
        logger.info("\n[DataFlow] Starting Phase 2/2: Analyzing main data flow...");
        long phase2StartTime = System.nanoTime();
        int processedCount2 = 0;
        int totalParsedFiles = parsedFiles.size();

        for (Map.Entry<Path, CompilationUnit> entry : parsedFiles.entrySet()) {
            try {
                Path file = entry.getKey();
                CompilationUnit cu = entry.getValue();
                List<String> fileFindings = new ArrayList<>();
                cu.accept(new TaintAnalysisVisitor(taintPropagatingMethods), fileFindings);
                if (!fileFindings.isEmpty()) {
                    allFindings.put(file.getFileName().toString(), fileFindings);
                }
            } catch (RuntimeException e) {
                logger.warning("[DataFlow] Error analyzing " + entry.getKey().getFileName() + ": " + e.getMessage());
            }
            processedCount2++;
            printProgress("Phase 2", processedCount2, totalParsedFiles, phase2StartTime);
        }
        if (totalParsedFiles > 0 && processedCount2 == totalParsedFiles) {
            System.out.println();
        }


        return new AnalysisResult(allFindings, failedFiles);
    }

    private void printProgress(String phase, int processed, int total, long startTime) {
        if (total == 0) return;
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
        private final Set<String> taintedVariables;
        private final Set<String> taintPropagatingMethods;

        private final Map<com.github.javaparser.ast.Node, String> resolvedSignatureCache = new HashMap<>();
        public TaintAnalysisVisitor(Set<String> taintPropagatingMethods) {
            this.taintPropagatingMethods = taintPropagatingMethods;
            this.taintedVariables = new HashSet<>();
        }

        @Override
        public void visit(MethodDeclaration n, List<String> findings) {
            this.taintedVariables.clear();

            for (Parameter param : n.getParameters()) {
                String paramType = param.getType().asString();
                if (paramType.contains("Event")) {
                    taintedVariables.add(param.getNameAsString());
                } else if (paramType.equals("Player")) {
                    taintedVariables.add(param.getNameAsString());
                } else if (paramType.equals("String[]")) {
                    taintedVariables.add(param.getNameAsString());
                }
            }

            if (n.getNameAsString().equals("onCommand") && n.getType().asString().equals("boolean")) {
                if (n.getParameterByType("String[]").isPresent()) {
                    taintedVariables.add(n.getParameterByType("String[]").get().getNameAsString());
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
                    if (isExpressionTainted(initializer)) {
                        taintedVariables.add(var.getNameAsString());
                    } else {
                        String varType = var.getType().asString();
                        if (varType.equals("Player") || varType.contains("Event")) {
                            if (initializer.isMethodCallExpr()) {
                                MethodCallExpr call = initializer.asMethodCallExpr();
                                if (call.getScope().isPresent() && isExpressionTainted(call.getScope().get())) {
                                    taintedVariables.add(var.getNameAsString());
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
            if (isExpressionTainted(n.getValue()) && n.getTarget().isNameExpr()) {
                taintedVariables.add(n.getTarget().asNameExpr().getNameAsString());
            }
        }

        @Override
        public void visit(MethodCallExpr call, List<String> findings) {
            super.visit(call, findings);

            String methodName = call.getNameAsString();
            if (DANGEROUS_SINKS.containsKey(methodName)) {
                if (call.getScope().isPresent() && isExpressionTainted(call.getScope().get())) {
                    if (! (methodName.equals("setOp") && isSafeSetOpCall(call))) {
                        String finding = String.format(
                            "CRITICAL DATA FLOW: Dangerous method '%s' called on tainted object at line %d.",
                            methodName, call.getRange().map(r -> r.begin.line).orElse(-1)
                        );
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
                            call, call.getRange().map(r -> r.begin.line).orElse(-1)
                        );
                        findings.add(finding);
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


        private boolean isExpressionTainted(Expression expr) {
            if (expr == null) { return false; }

            if (expr.isNameExpr()) {
                return taintedVariables.contains(expr.asNameExpr().getNameAsString());
            }

            if (expr.isMethodCallExpr()) {
                MethodCallExpr call = expr.asMethodCallExpr();
                String methodSignature = resolveMethodSignature(call);
                String methodName = call.getNameAsString();

                if (methodSignature == null) {
                    methodSignature = methodName;
                }

                if (methodSignature != null) {
                    final String finalMethodSignature = methodSignature;
                    boolean isCryptoPropagator = CRYPTO_TAINT_PROPAGATORS.stream()
                        .anyMatch(sig -> finalMethodSignature.startsWith(sig));
                    if (isCryptoPropagator) {
                        for (Expression arg : call.getArguments()) {
                            if (isExpressionTainted(arg)) {
                                return true;
                            }
                        }
                    }
                }

                if (call.getScope().isPresent()) {
                    Expression scope = call.getScope().get();
                    if (isExpressionTainted(scope)) {
                        return true;
                    }
                    
                    if (scope.isNameExpr()) {
                        String scopeVar = scope.asNameExpr().getNameAsString();
                        for (String source : TAINT_SOURCES) {
                            String[] parts = source.split("\\.");
                            if (parts.length == 2) {
                                String methodName2 = parts[1];
                                if (taintedVariables.contains(scopeVar) && methodName.equals(methodName2)) {
                                    return true;
                                }
                            }
                        }
                    }
                }

                if (taintPropagatingMethods.contains(methodSignature)) {
                    return true;
                }
            }

            if (expr.isBinaryExpr()) {
                BinaryExpr binaryExpr = expr.asBinaryExpr();
                if (binaryExpr.getOperator() == BinaryExpr.Operator.PLUS) {
                    return isExpressionTainted(binaryExpr.getLeft()) || isExpressionTainted(binaryExpr.getRight());
                }
            }
            
            if (expr.isCastExpr()) { return isExpressionTainted(expr.asCastExpr().getExpression()); }
            if (expr.isEnclosedExpr()) { return isExpressionTainted(expr.asEnclosedExpr().getInner()); }

            return false;
        }

        private String resolveMethodSignature(com.github.javaparser.ast.Node node) {
            if (resolvedSignatureCache.containsKey(node)) {
                return resolvedSignatureCache.get(node);
            }
            try {
                if (node instanceof MethodCallExpr) {
                    return ((MethodCallExpr) node).resolve().getQualifiedSignature();
                } else if (node instanceof MethodDeclaration) {
                    return ((MethodDeclaration) node).resolve().getQualifiedSignature();
                }
            } catch (Exception e) { }
            return null;
        }
    }

    private static class TaintPropagatingMethodVisitor extends VoidVisitorAdapter<Void> {
        private final Set<String> taintPropagatingMethods;
        private final TaintAnalysisVisitor internalTaintVisitor;

        public TaintPropagatingMethodVisitor(Set<String> taintPropagatingMethods) {
            this.taintPropagatingMethods = taintPropagatingMethods;
            this.internalTaintVisitor = new TaintAnalysisVisitor(Collections.emptySet());
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