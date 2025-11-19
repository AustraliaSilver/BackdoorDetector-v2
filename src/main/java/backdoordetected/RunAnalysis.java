package backdoordetected;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.List;
import java.util.Map;

public class RunAnalysis {
    public static void main(String[] args) {
        DataFlowAnalyzer analyzer = new DataFlowAnalyzer();
        Path testFile = Paths.get("src/main/java/backdoordetected/TestTaint.java").toAbsolutePath();
        Path workingDir = Paths.get("src/main/java").toAbsolutePath();

        System.out.println("Analyzing " + testFile);

        DataFlowAnalyzer.AnalysisResult result = analyzer.analyze(Collections.singletonList(testFile), workingDir);

        Map<String, List<String>> findings = result.findings();
        if (findings.isEmpty()) {
            System.out.println("No findings found.");
        } else {
            findings.forEach((file, list) -> {
                System.out.println("Findings for " + file + ":");
                list.forEach(System.out::println);
            });
        }

        if (!result.failedFiles().isEmpty()) {
            System.out.println("Failed files:");
            result.failedFiles().forEach(System.out::println);
        }
    }
}
