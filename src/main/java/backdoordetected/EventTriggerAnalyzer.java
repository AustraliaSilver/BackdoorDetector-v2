package backdoordetected;

import com.github.javaparser.ParseProblemException;
import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.expr.ArrayCreationExpr;
import com.github.javaparser.ast.expr.ArrayInitializerExpr;
import com.github.javaparser.ast.expr.CharLiteralExpr;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.ObjectCreationExpr;
import com.github.javaparser.ast.expr.StringLiteralExpr;
import com.github.javaparser.ast.type.PrimitiveType;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.logging.Logger;

public class EventTriggerAnalyzer {

    private static final Logger logger = Logger.getLogger(EventTriggerAnalyzer.class.getName());

    private static final Map<String, String> DANGEROUS_CALLS = new HashMap<>();
    static {
        DANGEROUS_CALLS.put("setOp", "Gain OP to player");
        DANGEROUS_CALLS.put("dispatchCommand", "Execute console command");
        DANGEROUS_CALLS.put("exec", "Command execution as console");
        DANGEROUS_CALLS.put("start", "Start a new process");
    }

    public EventTriggerAnalyzer() {
    }

    public AnalysisResult analyze(List<Path> javaFiles) {
        Map<Path, List<String>> allFindings = new HashMap<>();
        List<Path> failedFiles = new ArrayList<>();
        int totalFiles = javaFiles.size();
        long analysisStartTime = System.nanoTime();
        int processedCount = 0;
        int lastReportedProgress = -1;

        for (Path file : javaFiles) {
            try {
                CompilationUnit cu = StaticJavaParser.parse(file);

                
                cu.accept(new DeobfuscationVisitor(), null);

                cu.accept(new EventTriggerVisitor(file, allFindings), null);
            } catch (IOException e) {
                logger.warning("Failed to read file: " + file.getFileName());
            } catch (ParseProblemException e) {
                failedFiles.add(file);
                logger.warning("Failed to parse file (syntax error): " + file.getFileName());
            }
            processedCount++;

            int currentProgress = (processedCount * 100) / totalFiles;
            if (currentProgress > lastReportedProgress && (currentProgress % 10 == 0 || processedCount % 200 == 0)) {
                long elapsedTimeNs = System.nanoTime() - analysisStartTime;
                if (processedCount > 0 && elapsedTimeNs > 0) {
                    double timePerFile = (double) elapsedTimeNs / processedCount;
                    long remainingFiles = totalFiles - processedCount;
                    long estimatedTimeRemainingNs = (long) (remainingFiles * timePerFile);
                    long etaSeconds = estimatedTimeRemainingNs / 1_000_000_000;

                    System.out.printf("\r[PROGRESS] Analyzing source files: %d%% (%d/%d). ETA: ~%d seconds...",
                            currentProgress, processedCount, totalFiles, etaSeconds);
                }
                lastReportedProgress = currentProgress;
            }
        }
        return new AnalysisResult(allFindings, failedFiles);
    }

    private static class EventTriggerVisitor extends VoidVisitorAdapter<Void> {
        private final Map<Path, List<String>> allFindings;
        private final Path currentFile;

        public EventTriggerVisitor(Path currentFile, Map<Path, List<String>> allFindings) {
            this.currentFile = currentFile;
            this.allFindings = allFindings;
        }

        @Override
        public void visit(MethodDeclaration n, Void arg) {
            super.visit(n, arg);

            if (n.isAnnotationPresent("EventHandler")) {
                List<String> methodFindings = new ArrayList<>();

                n.findAll(MethodCallExpr.class).forEach(call -> {
                    String methodName = call.getNameAsString();
                    if (DANGEROUS_CALLS.containsKey(methodName)) {
                        String description = DANGEROUS_CALLS.get(methodName);
                        String args = call.getArguments().toString();
                        methodFindings.add("Found suspicious method call '" + methodName + "' with args " + args
                                + " inside event handler: "
                                + description);
                    }
                });

                if (!methodFindings.isEmpty()) {
                    allFindings.computeIfAbsent(currentFile, k -> new ArrayList<>()).addAll(methodFindings);
                }
            }
        }
    }

    
    private static class DeobfuscationVisitor extends VoidVisitorAdapter<Void> {
        private final Map<String, String> stringConstants = new HashMap<>();

        @Override
        public void visit(MethodDeclaration n, Void arg) {
            stringConstants.clear();
            super.visit(n, arg);
        }

        @Override
        public void visit(com.github.javaparser.ast.body.VariableDeclarator n, Void arg) {
            super.visit(n, arg);
            if (n.getType().asString().equals("String") && n.getInitializer().isPresent()) {
                n.getInitializer().get().ifStringLiteralExpr(s -> {
                    stringConstants.put(n.getNameAsString(), s.asString());
                });
            }
        }

        @Override
        public void visit(MethodCallExpr n, Void arg) {
            super.visit(n, arg);

            
            if ("decode".equals(n.getNameAsString()) && n.getArguments().size() == 1) {
                n.getScope().ifPresent(scope -> {
                    if (scope.isMethodCallExpr()) {
                        MethodCallExpr scopeCall = scope.asMethodCallExpr();
                        if ("getDecoder".equals(scopeCall.getNameAsString()) && scopeCall.getScope().isPresent()) {
                            String scopeName = scopeCall.getScope().get().toString();
                            if ("Base64".equals(scopeName)) {
                                try {
                                    String encoded = null;
                                    if (n.getArgument(0).isStringLiteralExpr()) {
                                        encoded = n.getArgument(0).asStringLiteralExpr().asString();
                                    } else if (n.getArgument(0).isNameExpr()) {
                                        String varName = n.getArgument(0).asNameExpr().getNameAsString();
                                        encoded = stringConstants.get(varName);
                                    }

                                    if (encoded != null) {
                                        byte[] decodedBytes = Base64.getDecoder().decode(encoded);
                                        String decodedString = new String(decodedBytes, StandardCharsets.UTF_8);

                                        
                                        if (n.getParentNode().isPresent()
                                                && n.getParentNode().get() instanceof ObjectCreationExpr) {
                                            ObjectCreationExpr parent = (ObjectCreationExpr) n.getParentNode().get();
                                            if (parent.getType().getNameAsString().equals("String")) {
                                                parent.replace(new StringLiteralExpr(decodedString));
                                                return;
                                            }
                                        }

                                        
                                        
                                        n.replace(new StringLiteralExpr(decodedString));
                                    }
                                } catch (IllegalArgumentException e) {
                                    
                                }
                            }
                        }
                    }
                });
            }
        }

        @Override
        public void visit(ObjectCreationExpr n, Void arg) {
            super.visit(n, arg);

            
            if ("String".equals(n.getType().getNameAsString()) && n.getArguments().size() == 1) {
                n.getArgument(0).ifArrayCreationExpr(arrayCreationExpr -> {
                    if (arrayCreationExpr.getElementType().isPrimitiveType() && arrayCreationExpr.getElementType()
                            .asPrimitiveType().getType() == PrimitiveType.Primitive.CHAR) {
                        arrayCreationExpr.getInitializer().ifPresent(initializer -> {
                            StringBuilder sb = new StringBuilder();
                            boolean allChars = true;
                            for (Node value : initializer.getValues()) {
                                if (value instanceof CharLiteralExpr) {
                                    sb.append(((CharLiteralExpr) value).asChar());
                                } else {
                                    allChars = false;
                                    break;
                                }
                            }
                            if (allChars) {
                                n.replace(new StringLiteralExpr(sb.toString()));
                            }
                        });
                    }
                });
            }
        }
    }

    public record AnalysisResult(Map<Path, List<String>> findings, List<Path> failedFiles) {
    }
}