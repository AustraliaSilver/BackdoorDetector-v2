package backdoordetected.models;

import backdoordetected.utils.ScanMode;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

public record AnalysisContext(
    Path pluginPath,
    Path workingDir,
    List<Path> javaFiles,
    List<Path> classFiles,
    Map<Path, Path> javaToClassMap,
    ScanMode scanMode,
    String workerName) {
  public boolean isModernScanMode() {
    return scanMode == ScanMode.AI_MODERN;
  }

  public boolean isBackdoorFocusMode() {
    return scanMode == ScanMode.AI_BACKDOOR_FOCUS;
  }

  public int getTotalFileCount() {
    return javaFiles.size() + classFiles.size();
  }
}
