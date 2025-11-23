package backdoordetected.models;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;

public record ScanResult(
        boolean isMalicious,
        int confidence,
        String severity,
        String vulnerabilityType,
        String reasoning,
        Map<Path, List<String>> findings) {
    public ScanResult {
        if (confidence < 0 || confidence > 100) {
            throw new IllegalArgumentException("Confidence must be between 0 and 100");
        }
        if (severity == null || severity.isBlank()) {
            throw new IllegalArgumentException("Severity cannot be null or blank");
        }
    }

    public static ScanResult error(Throwable cause) {
        return new ScanResult(
                false,
                0,
                "ERROR",
                "Scan Failed",
                "Scan failed: " + cause.getMessage(),
                Map.of());
    }

    public static ScanResult clean() {
        return new ScanResult(
                false,
                95,
                "NONE",
                "Clean",
                "No malicious patterns detected",
                Map.of());
    }
}
