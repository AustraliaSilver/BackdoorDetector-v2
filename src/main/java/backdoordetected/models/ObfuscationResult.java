package backdoordetected.models;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ObfuscationResult extends PluginAnalysisResult {
  private final int score;
  private final List<String> warnings;
  private final boolean isHeavilyObfuscated;

  public ObfuscationResult(
      String analyzerName,
      Map<String, List<String>> genericFindings,
      boolean hasHighSeverity,
      boolean hasLowSeverity,
      int score,
      List<String> warnings,
      boolean isHeavilyObfuscated) {
    super(analyzerName, genericFindings, hasHighSeverity, hasLowSeverity);
    this.score = score;
    this.warnings = warnings;
    this.isHeavilyObfuscated = isHeavilyObfuscated;
  }

  public static ObfuscationResult empty(String analyzerName) {
    return new ObfuscationResult(analyzerName, new HashMap<>(), false, false, 0, List.of(), false);
  }

  public int score() {
    return score;
  }

  public List<String> warnings() {
    return warnings;
  }

  public boolean isHeavilyObfuscated() {
    return isHeavilyObfuscated;
  }
}
