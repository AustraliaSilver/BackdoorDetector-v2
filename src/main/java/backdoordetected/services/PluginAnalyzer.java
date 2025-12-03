package backdoordetected.services;

import backdoordetected.models.PluginAnalysisResult;
import backdoordetected.utils.ScanMode;
import java.nio.file.Path;
import java.util.List;

public interface PluginAnalyzer {
  String getName();

  PluginAnalysisResult analyze(
      Path pluginPath,
      List<Path> javaFiles,
      List<Path> classFiles,
      Path workingDir,
      ScanMode scanMode,
      String workerName)
      throws Exception;

  default boolean canRun(ScanMode scanMode) {
    return true;
  }
}
