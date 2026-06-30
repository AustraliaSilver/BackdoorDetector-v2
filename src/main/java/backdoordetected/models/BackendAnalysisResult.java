package backdoordetected.models;

import java.util.List;

public record BackendAnalysisResult(
    boolean isMalicious,
    String confidence,
    String threatType,
    String summary,
    String analysis,
    List<String> keyIndicators,
    int riskScore,
    boolean cached,
    long elapsedMs
) {
  public String formatForDisplay() {
    StringBuilder sb = new StringBuilder();
    sb.append(isMalicious ? "MALICIOUS" : "CLEAN").append("\n");
    sb.append("Confidence: ").append(confidence).append("\n");
    sb.append("Threat Type: ").append(threatType).append("\n");
    sb.append("Risk Score: ").append(riskScore).append("/100").append("\n");
    sb.append("Summary: ").append(summary).append("\n");
    if (!keyIndicators.isEmpty()) {
      sb.append("Key Indicators:\n");
      for (String ind : keyIndicators) {
        sb.append("  • ").append(ind).append("\n");
      }
    }
    if (cached) {
      sb.append("(cached from backend, ").append(elapsedMs).append("ms)\n");
    }
    return sb.toString();
  }
}
