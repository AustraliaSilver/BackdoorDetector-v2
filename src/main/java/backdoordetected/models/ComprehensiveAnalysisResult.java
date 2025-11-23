package backdoordetected.models;

import backdoordetected.detection.LMXBackdoorDetector;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

public record ComprehensiveAnalysisResult(
        Map<Path, List<String>> eventFindings,
        List<Path> failedFiles,
        LMXBackdoorDetector.BackdoorScanResult backdoorScan,
        boolean lmxStringLiteralFound,
        String directoryTree,
        List<Path> suspiciousFiles,
        String combinedCode) {
    public boolean hasFindings() {
        return !eventFindings.isEmpty() || backdoorScan.hasAnyBackdoor() || lmxStringLiteralFound;
    }

    public boolean hasKnownBackdoor() {
        return backdoorScan.hasLMXBackdoor || backdoorScan.hasOpenEctasy || lmxStringLiteralFound;
    }

    public boolean hasHighSeverityFindings() {
        if (hasKnownBackdoor()) {
            return true;
        }

        for (List<String> findings : eventFindings.values()) {
            for (String finding : findings) {
                String upperFinding = finding.toUpperCase();
                if (upperFinding.startsWith("CRITICAL:") ||
                        upperFinding.startsWith("HIGH:") ||
                        upperFinding.startsWith("MEDIUM:")) {
                    return true;
                }
            }
        }

        return false;
    }
}
