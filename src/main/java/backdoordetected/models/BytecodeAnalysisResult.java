package backdoordetected.models;

import java.util.List;
import java.util.Map;

public class BytecodeAnalysisResult extends PluginAnalysisResult {
  private final List<String> rawFindings;

  public BytecodeAnalysisResult(
      String analyzerName,
      Map<String, List<String>> genericFindings,
      boolean hasHighSeverity,
      boolean hasLowSeverity,
      List<String> rawFindings) {
    super(analyzerName, genericFindings, hasHighSeverity, hasLowSeverity);
    this.rawFindings = rawFindings;
  }

  public List<String> getRawFindings() {
    return rawFindings;
  }

}
