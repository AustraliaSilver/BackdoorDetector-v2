package backdoordetected;

import static org.junit.jupiter.api.Assertions.*;

import backdoordetected.models.ComprehensiveAnalysisResult;
import backdoordetected.services.AnalysisCoordinator;
import backdoordetected.utils.ScanMode;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import backdoordetected.models.SootAnalysisResult;
import backdoordetected.models.TaintFlow;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

class LiteBansIntegrationTest {

  private static final Path JAR = Path.of("temp", "LiteBans.jar");
  private static AnalysisCoordinator coordinator;

  @BeforeAll
  static void setUp() {
    coordinator = new AnalysisCoordinator();
  }

  @Test
  @Timeout(600)
  void scanIdentifiesFindingsButNotKnownBackdoor() throws Exception {
    assertTrue(Files.exists(JAR), "JAR must exist at: " + JAR);

    ComprehensiveAnalysisResult result = coordinator.analyze(
        JAR, ScanMode.BYTECODE, "litebans-test");

    assertNotNull(result, "Analysis result should not be null");
    assertNotNull(result.eventFindings(), "Event findings should not be null");

    assertFalse(result.hasKnownBackdoor(),
        "LiteBans should NOT be flagged as a known backdoor");

    // Check for findings under any key
    assertFalse(result.eventFindings().isEmpty(),
        "LiteBans should have some findings (bytecode or soot)");

    // Soot taint flows (dispatchCommand via reflection)
    Optional<SootAnalysisResult> sootResult = result.getAnalyzerResult(
        "sootTaintAnalyzer", SootAnalysisResult.class);
    assertTrue(sootResult.isPresent(), "Soot analysis result should be present");
    assertFalse(sootResult.get().taintFlows().isEmpty(),
        "LiteBans should have Soot taint flows");

    TaintFlow firstFlow = sootResult.get().taintFlows().get(0);
    assertTrue(firstFlow.sink().contains("dispatchCommand"),
        "Soot taint sink should reference dispatchCommand");
  }
}
