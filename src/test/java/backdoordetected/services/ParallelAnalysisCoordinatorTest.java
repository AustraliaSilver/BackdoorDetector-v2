package backdoordetected.services;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.Path;
import java.util.Collections;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ParallelAnalysisCoordinatorTest {

  @TempDir
  Path tempDir;

  @Test
  void emptyInputsWithEventTriggerModeDontThrow() {
    ParallelAnalysisCoordinator coordinator = new ParallelAnalysisCoordinator(2);
    try {
      ParallelAnalysisCoordinator.ParallelAnalysisResult result =
          coordinator.analyzeParallel(
              Collections.emptyList(),
              Collections.emptyList(),
              tempDir,
              false);
      assertNotNull(result);
      assertTrue(result.getEventFindings().isEmpty());
      assertTrue(result.getFailedFiles().isEmpty());
      assertTrue(result.getBytecodeFindings().isEmpty());
    } finally {
      coordinator.shutdown();
    }
  }

  @Test
  void emptyInputsWithDataFlowModeDontThrow() {
    ParallelAnalysisCoordinator coordinator = new ParallelAnalysisCoordinator(2);
    try {
      ParallelAnalysisCoordinator.ParallelAnalysisResult result =
          coordinator.analyzeParallel(
              Collections.emptyList(),
              Collections.emptyList(),
              tempDir,
              true);
      assertNotNull(result);
      assertTrue(result.getEventFindings().isEmpty());
      assertTrue(result.getFailedFiles().isEmpty());
      assertTrue(result.getBytecodeFindings().isEmpty());
    } finally {
      coordinator.shutdown();
    }
  }

  @Test
  void handlesMissingWorkingDir() {
    Path missingDir = tempDir.resolve("nonexistent");
    ParallelAnalysisCoordinator coordinator = new ParallelAnalysisCoordinator(2);
    try {
      ParallelAnalysisCoordinator.ParallelAnalysisResult result =
          coordinator.analyzeParallel(
              Collections.emptyList(),
              Collections.emptyList(),
              missingDir,
              false);
      assertNotNull(result);
    } finally {
      coordinator.shutdown();
    }
  }

  @Test
  void shutdownIsIdempotent() {
    ParallelAnalysisCoordinator coordinator = new ParallelAnalysisCoordinator(2);
    coordinator.shutdown();
    coordinator.shutdown();
  }

  @Test
  void singleThreadDoesNotThrow() {
    ParallelAnalysisCoordinator coordinator = new ParallelAnalysisCoordinator(1);
    try {
      ParallelAnalysisCoordinator.ParallelAnalysisResult result =
          coordinator.analyzeParallel(
              Collections.emptyList(),
              Collections.emptyList(),
              tempDir,
              false);
      assertNotNull(result);
    } finally {
      coordinator.shutdown();
    }
  }

  @Test
  void manyThreadsDoesNotThrow() {
    ParallelAnalysisCoordinator coordinator = new ParallelAnalysisCoordinator(16);
    try {
      ParallelAnalysisCoordinator.ParallelAnalysisResult result =
          coordinator.analyzeParallel(
              Collections.emptyList(),
              Collections.emptyList(),
              tempDir,
              false);
      assertNotNull(result);
    } finally {
      coordinator.shutdown();
    }
  }

  @Test
  void analyzeAfterShutdownThrows() {
    ParallelAnalysisCoordinator coordinator = new ParallelAnalysisCoordinator(2);
    coordinator.shutdown();
    assertThrows(RuntimeException.class, () ->
        coordinator.analyzeParallel(
            Collections.emptyList(),
            Collections.emptyList(),
            tempDir,
            false));
  }
}
