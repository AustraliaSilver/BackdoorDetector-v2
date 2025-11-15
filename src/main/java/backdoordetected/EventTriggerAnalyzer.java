package backdoordetected;

import com.github.javaparser.ParseProblemException;
import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.logging.Logger;

public class EventTriggerAnalyzer {

    private static final Logger logger = Logger.getLogger(EventTriggerAnalyzer.class.getName());

    private static final Pattern BASE64_DECODE_PATTERN = Pattern.compile("Base64\\.getDecoder\\(\\)\\.decode\\(\"([a-zA-Z0-9+/=]+)\"\\)");
    private static final Pattern CHAR_ARRAY_STRING_PATTERN = Pattern.compile("new String\\s*\\(\\s*new char\\[\\]\\s*\\{([^}]+)\\}");

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
                String originalContent = Files.readString(file, StandardCharsets.UTF_8);
                String deobfuscatedContent = preprocessContent(originalContent);

                CompilationUnit cu = StaticJavaParser.parse(deobfuscatedContent);
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

                    System.out.printf("\r[PROGRESS] Analyzing source files: %d%% (%d/%d). ETA: ~%d seconds...", currentProgress, processedCount, totalFiles, etaSeconds);
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
                        methodFindings.add("Found suspicious method call '" + methodName + "' inside event handler: " + description);
                    }
                });

                if (!methodFindings.isEmpty()) {
                    allFindings.computeIfAbsent(currentFile, k -> new ArrayList<>()).addAll(methodFindings);
                }
            }
        }
    }

    private String preprocessContent(String content) {
        String previousContent = "";
        String currentContent = content;
        int maxIterations = 5;
        int iteration = 0;

        do {
            previousContent = currentContent;

            StringBuffer sb = new StringBuffer();
            Matcher base64Matcher = BASE64_DECODE_PATTERN.matcher(previousContent);
            while (base64Matcher.find()) {
                try {
                    String encodedString = base64Matcher.group(1);
                    byte[] decodedBytes = Base64.getDecoder().decode(encodedString);
                    String decodedString = new String(decodedBytes, StandardCharsets.UTF_8);
                    base64Matcher.appendReplacement(sb, Matcher.quoteReplacement("\"" + decodedString + "\""));
                } catch (IllegalArgumentException e) {  }
            }
            base64Matcher.appendTail(sb);
            currentContent = sb.toString();

            sb.setLength(0);
            Matcher charArrayMatcher = CHAR_ARRAY_STRING_PATTERN.matcher(currentContent);
            while (charArrayMatcher.find()) {
                String charList = charArrayMatcher.group(1);
                String[] chars = charList.replace("'", "").replace("\"", "").split(",");
                StringBuilder resolvedString = new StringBuilder();
                for (String c : chars) {
                    resolvedString.append(c.trim());
                }
                charArrayMatcher.appendReplacement(sb, Matcher.quoteReplacement("\"" + resolvedString.toString() + "\""));
            }
            charArrayMatcher.appendTail(sb);
            currentContent = sb.toString();

            iteration++;
        } while (!currentContent.equals(previousContent) && iteration < maxIterations);

        return currentContent;
    }

    public record AnalysisResult(Map<Path, List<String>> findings, List<Path> failedFiles) {
    }
}