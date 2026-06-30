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
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

class CitizensIntegrationTest {

  private static final Path JAR = Path.of("temp", "Citizens.jar");
  private static AnalysisCoordinator coordinator;

  @BeforeAll
  static void setUp() {
    coordinator = new AnalysisCoordinator();
  }

  @Test
  @Timeout(300)
  void scanIdentifiesFindingsButNotKnownBackdoor() throws Exception {
    assertTrue(Files.exists(JAR), "JAR must exist at: " + JAR);

    ComprehensiveAnalysisResult result = coordinator.analyze(
        JAR, ScanMode.BYTECODE, "citizens-test");

    assertNotNull(result, "Analysis result should not be null");
    assertNotNull(result.eventFindings(), "Event findings should not be null");

    assertFalse(result.hasKnownBackdoor(),
        "Citizens should NOT be flagged as a known backdoor");

    Map<Path, List<String>> findings = result.eventFindings();
    List<String> bcFindings = findings.get(Path.of("BYTECODE_ANALYSIS"));

    assertNotNull(bcFindings, "Should have BYTECODE_ANALYSIS findings");
    assertFalse(bcFindings.isEmpty(),
        "Bytecode analysis should detect patterns in Citizens");

    String all = String.join(" ", bcFindings);

    // Method.invoke used in EventListen for Paper event registration
    assertTrue(all.contains("Method.invoke") || all.contains("MethodHandle"),
        "Should flag Method.invoke (NPC event reflection)");

    // Class.forName for Paper API detection
    assertTrue(all.contains("Class.forName"),
        "Should detect Class.forName calls");

    // Soot taint flows from EventListen to Method.invoke
    Optional<SootAnalysisResult> sootResult = result.getAnalyzerResult(
        "sootTaintAnalyzer", SootAnalysisResult.class);
    if (sootResult.isPresent()) {
      assertFalse(sootResult.get().taintFlows().isEmpty(),
          "Citizens should have Soot taint flows (EventListen NPC events)");
    }

    assertNotNull(result.obfuscationResult(),
        "Obfuscation analysis should have run");
  }
}
