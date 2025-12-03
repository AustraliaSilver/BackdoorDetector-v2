package backdoordetected.models;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;

public class DataFlowAnalysisResult extends PluginAnalysisResult {
  private final Map<String, List<String>> fileFindings;
  private final List<Path> failedFiles;

  public DataFlowAnalysisResult(
      String analyzerName,
      Map<String, List<String>> genericFindings,
      boolean hasHighSeverity,
      boolean hasLowSeverity,
      Map<String, List<String>> fileFindings,
      List<Path> failedFiles) {
    super(analyzerName, genericFindings, hasHighSeverity, hasLowSeverity);
    this.fileFindings = fileFindings;
    this.failedFiles = failedFiles;
  }

  public Map<String, List<String>> getFileFindings() {
    return fileFindings;
  }

  public List<Path> getFailedFiles() {
    return failedFiles;
  }

}
