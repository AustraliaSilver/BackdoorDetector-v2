package backdoordetected.models;

import backdoordetected.detection.LMXBackdoorDetector;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public record ComprehensiveAnalysisResult(
    Map<Path, List<String>> eventFindings,
    List<Path> failedFiles,
    LMXBackdoorDetector.BackdoorScanResult backdoorScan,
    boolean lmxStringLiteralFound,
    String directoryTree,
    List<Path> suspiciousFiles,
    String combinedCode,
    Map<String, PluginAnalysisResult> pluginAnalysisResults) {

  public boolean hasFindings() {
    if (!eventFindings.isEmpty() || backdoorScan.hasAnyBackdoor() || lmxStringLiteralFound) {
      return true;
    }
    for (PluginAnalysisResult result : pluginAnalysisResults.values()) {
      if (result.hasAnyFindings()) {
        return true;
      }
    }
    return false;
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
        if (upperFinding.startsWith("CRITICAL:")
            || upperFinding.startsWith("HIGH:")
            || upperFinding.startsWith("MEDIUM:")) {
          return true;
        }
      }
    }

    for (PluginAnalysisResult result : pluginAnalysisResults.values()) {
      if (result.hasHighSeverityFindings()) {
        return true;
      }
    }
    return false;
  }

  public <T extends PluginAnalysisResult> Optional<T> getAnalyzerResult(
      String analyzerName, Class<T> resultType) {
    PluginAnalysisResult result = pluginAnalysisResults.get(analyzerName);
    if (resultType.isInstance(result)) {
      return Optional.of(resultType.cast(result));
    }
    return Optional.empty();
  }

  public ObfuscationResult obfuscationResult() {
    return getAnalyzerResult("ObfuscationAnalyzer", ObfuscationResult.class)
        .orElse(ObfuscationResult.empty("ObfuscationAnalyzer"));
  }
}
