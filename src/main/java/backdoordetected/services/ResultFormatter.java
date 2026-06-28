package backdoordetected.services;

import backdoordetected.detection.LMXBackdoorDetector;
import backdoordetected.models.ComprehensiveAnalysisResult;
import backdoordetected.models.PluginAnalysisResult;
import backdoordetected.utils.StandaloneLogger;
import java.nio.file.Path;
import java.util.Map;
import java.util.logging.Logger;

public class ResultFormatter {
  private static final Logger logger = StandaloneLogger.getLogger();

  public String formatResult(ComprehensiveAnalysisResult comprehensiveResult) {
    StringBuilder result = new StringBuilder();
    result.append("### Analysis Report ###\n\n");

    LMXBackdoorDetector.BackdoorScanResult backdoorScan = comprehensiveResult.backdoorScan();

    if (backdoorScan.hasAnyBackdoor()) {
      result.append("## Known Backdoor Detected!\n");
      result.append("**Malicious:** YES\n");
      result.append("**Confidence:** 100%\n");
      result.append("**Severity:** CRITICAL\n");
      result.append("**Vulnerability Type:** Hardcoded Backdoor\n\n");
      result.append("### REASONING\n");

      if (backdoorScan.hasLMXBackdoor) {
        result.append(
            "- Confirmed: L.M.X backdoor signature detected (sequential L/M/X directory structure).\n");
      }
      if (backdoorScan.hasOpenEctasy) {
        result.append(
            "- Confirmed: OpenEctasy malware signature detected ('bodyalhoha' directory).\n");
      }
      result.append("This is an unequivocally known and critical backdoor/malware pattern.\n\n");
    } else {
      result.append("## No Known Hardcoded Backdoor Signatures Detected.\n\n");
    }

    for (Map.Entry<String, PluginAnalysisResult> entry :
        comprehensiveResult.pluginAnalysisResults().entrySet()) {
      PluginAnalysisResult pluginResult = entry.getValue();
      if (pluginResult.hasAnyFindings()) {
        result.append("## Analyzer: ").append(pluginResult.getAnalyzerName()).append("\n");
        result
            .append("**Status:** ")
            .append(pluginResult.hasHighSeverityFindings() ? "SUSPICIOUS" : "OK")
            .append("\n");
        result
            .append("**Severity:** ")
            .append(
                pluginResult.hasHighSeverityFindings()
                    ? "HIGH"
                    : (pluginResult.hasLowSeverityFindings() ? "MEDIUM" : "LOW"))
            .append("\n");

        if (!pluginResult.getFindings().isEmpty()) {
          result.append("### Findings from ").append(pluginResult.getAnalyzerName()).append(":\n");
          pluginResult
              .getFindings()
              .forEach(
                  (key, findingsList) -> {
                    result.append("  - ").append(key).append(":\n");
                    findingsList.forEach(f -> result.append("    - ").append(f).append("\n"));
                  });
        }
        result.append("\n");
      }
    }

    if (comprehensiveResult.eventFindings().containsKey(Path.of("BYTECODE_ANALYSIS"))) {
      result.append("## Analyzer: Bytecode Analysis\n");
      result.append("**Status:** SUSPICIOUS\n");
      result.append("**Severity:** HIGH\n");
      result.append("### Findings from Bytecode Analysis:\n");
      comprehensiveResult.eventFindings().get(Path.of("BYTECODE_ANALYSIS")).stream()
          .forEach(
              finding -> {
                result.append("  - ").append(finding).append("\n");
              });
    }

    if (comprehensiveResult.eventFindings().containsKey(Path.of("SOOT_ANALYSIS"))) {
      result.append("## Analyzer: Soot Taint Analysis\n");
      result.append("**Status:** SUSPICIOUS\n");
      result.append("**Severity:** CRITICAL\n");
      result.append("### Taint Flows Detected:\n");
      comprehensiveResult.eventFindings().get(Path.of("SOOT_ANALYSIS")).stream()
          .forEach(
              finding -> {
                result.append("  - ").append(finding).append("\n");
              });
    }
    result.append("### Overall Analysis Summary ###\n");
    result
        .append("**Overall Malicious:** ")
        .append(comprehensiveResult.hasHighSeverityFindings() ? "HIGHLY LIKELY" : "NO")
        .append("\n");
    result
        .append("**Overall Confidence:** ")
        .append(comprehensiveResult.hasHighSeverityFindings() ? "HIGH" : "MEDIUM")
        .append("\n");
    result
        .append("**Overall Severity:** ")
        .append(
            comprehensiveResult.hasHighSeverityFindings()
                ? "CRITICAL/HIGH"
                : (comprehensiveResult.hasFindings() ? "MEDIUM/LOW" : "NONE"))
        .append("\n");
    result.append("\n");
    result.append("Full report details are available in logs.");

    return result.toString();
  }
}
