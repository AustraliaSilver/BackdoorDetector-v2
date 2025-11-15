package backdoordetected;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public record AnalysisResult(String analyzerName, Map<Path, List<String>> findings, List<Path> failedFiles) {
    public boolean hasFindings() {
        return findings != null && !findings.isEmpty();
    }
}