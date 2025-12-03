package backdoordetected.models;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;

public class EventTriggerAnalysisResult extends PluginAnalysisResult {
  private final Map<Path, List<String>> fileFindings;
  private final List<Path> failedFiles;

  public EventTriggerAnalysisResult(
      String analyzerName,
      Map<String, List<String>> genericFindings,
      boolean hasHighSeverity,
      boolean hasLowSeverity,
      Map<Path, List<String>> fileFindings,
      List<Path> failedFiles) {
    super(analyzerName, genericFindings, hasHighSeverity, hasLowSeverity);
    this.fileFindings = fileFindings;
    this.failedFiles = failedFiles;
  }

  public Map<Path, List<String>> getFileFindings() {
    return fileFindings;
  }

  public List<Path> getFailedFiles() {
    return failedFiles;
  }
}
