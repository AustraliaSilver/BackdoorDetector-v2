package backdoordetected;

import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.logging.Logger;

public class SandboxAnalyzer {

    private static final Logger logger = StandaloneLogger.getLogger();

    private static final Map<String, String> DANGEROUS_CALLS = new HashMap<>();

    static {
        DANGEROUS_CALLS.put("setOp", "CRITICAL: Grants OP status to a player");
        DANGEROUS_CALLS.put("dispatchCommand", "HIGH: Dispatches a command as the console");
        DANGEROUS_CALLS.put("exec", "CRITICAL: Executes system commands");
        DANGEROUS_CALLS.put("start", "CRITICAL: Starts a system process (ProcessBuilder)");
        DANGEROUS_CALLS.put("invoke", "HIGH: Uses reflection, could be hiding malicious calls");
        DANGEROUS_CALLS.put("openConnection", "HIGH: Creates network connections");
        DANGEROUS_CALLS.put("defineClass", "CRITICAL: Loads a class from bytes, potential for dynamic code execution");
    }

    public SandboxAnalyzer() {
    }

    public Map<String, List<String>> analyze(List<Path> javaFiles) {
        Map<String, List<String>> eventFindings = new HashMap<>();
        for (Path file : javaFiles) {
            try {
                CompilationUnit cu = StaticJavaParser.parse(file);
                EventHandlerVisitor visitor = new EventHandlerVisitor(eventFindings);
                visitor.visit(cu, null);
            } catch (IOException e) {
                logger.warning("[Sandbox] Failed to parse " + file.getFileName() + ". Reason: " + e.getClass().getSimpleName());
            }
        }
        return eventFindings;
    }

    private static class EventHandlerVisitor extends VoidVisitorAdapter<Void> {
        private final Map<String, List<String>> eventFindings;

        public EventHandlerVisitor(Map<String, List<String>> eventFindings) {
            this.eventFindings = eventFindings;
        }

        @Override
        public void visit(MethodDeclaration n, Void arg) {
            super.visit(n, arg);

            if (n.isAnnotationPresent("EventHandler")) {
                if (n.getParameters().size() == 1) {
                    String eventName = n.getParameter(0).getType().asString();
                    Set<String> findings = new HashSet<>();

                    n.findAll(MethodCallExpr.class).forEach(call -> {
                        String methodName = call.getNameAsString();
                        if (DANGEROUS_CALLS.containsKey(methodName)) {
                            findings.add(DANGEROUS_CALLS.get(methodName));
                        }
                    });

                    if (!findings.isEmpty()) {
                        eventFindings.computeIfAbsent(eventName, k -> new ArrayList<>()).addAll(findings);
                    }
                }
            }
        }
    }
}