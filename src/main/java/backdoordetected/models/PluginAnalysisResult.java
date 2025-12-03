package backdoordetected.models;

import java.util.List;
import java.util.Map;

public abstract class PluginAnalysisResult {
  private final String analyzerName;
  private final Map<String, List<String>> findings;
  private final boolean hasHighSeverityFindings;
  private final boolean hasLowSeverityFindings;

  protected PluginAnalysisResult(
      String analyzerName,
      Map<String, List<String>> findings,
      boolean hasHighSeverityFindings,
      boolean hasLowSeverityFindings) {
    this.analyzerName = analyzerName;
    this.findings = findings;
    this.hasHighSeverityFindings = hasHighSeverityFindings;
    this.hasLowSeverityFindings = hasLowSeverityFindings;
  }

  public String getAnalyzerName() {
    return analyzerName;
  }

  public Map<String, List<String>> getFindings() {
    return findings;
  }

  public boolean hasHighSeverityFindings() {
    return hasHighSeverityFindings;
  }

  public boolean hasLowSeverityFindings() {
    return hasLowSeverityFindings;
  }

  public boolean hasAnyFindings() {
    return hasHighSeverityFindings || hasLowSeverityFindings || !findings.isEmpty();
  }
}
