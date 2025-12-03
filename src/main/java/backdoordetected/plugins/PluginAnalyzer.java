package backdoordetected.plugins;

import backdoordetected.models.AnalysisContext;
import backdoordetected.models.PluginAnalysisResult;
import backdoordetected.utils.ScanMode;
import java.util.Set;

public interface PluginAnalyzer {
  PluginAnalysisResult analyze(AnalysisContext context);

  String getName();

  default int getPriority() {
    return 50;
  }

  default Set<ScanMode> getSupportedModes() {
    return Set.of();
  }

  default boolean requiresDecompiledCode() {
    return true;
  }

  default boolean supportsParallelExecution() {
    return true;
  }

  default String getDescription() {
    return "No description provided";
  }
}
