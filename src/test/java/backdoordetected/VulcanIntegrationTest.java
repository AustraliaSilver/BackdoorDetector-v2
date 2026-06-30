package backdoordetected;

import static org.junit.jupiter.api.Assertions.*;

import backdoordetected.models.ComprehensiveAnalysisResult;
import backdoordetected.services.AnalysisCoordinator;
import backdoordetected.utils.ScanMode;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

class VulcanIntegrationTest {

  private static final Path JAR = Path.of("temp", "Vulcan-2.9.7.23.jar");
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
        JAR, ScanMode.BYTECODE, "vulcan-test");

    assertNotNull(result, "Analysis result should not be null");
    assertNotNull(result.eventFindings(), "Event findings should not be null");

    assertFalse(result.hasKnownBackdoor(),
        "Vulcan should NOT be flagged as a known backdoor");

    Map<Path, List<String>> findings = result.eventFindings();
    List<String> bcFindings = findings.get(Path.of("BYTECODE_ANALYSIS"));

    assertNotNull(bcFindings, "Should have BYTECODE_ANALYSIS findings");
    assertFalse(bcFindings.isEmpty(),
        "Bytecode analysis should detect patterns in Vulcan");

    String all = String.join(" ", bcFindings);

    // Method.invoke in check execution system
    assertTrue(all.contains("Method.invoke"),
        "Should flag Method.invoke (anti-cheat check system)");

    // Class.forName for Paper/Folia detection
    assertTrue(all.contains("Class.forName"),
        "Should detect Class.forName calls");

    // Obfuscation analysis should have run
    assertNotNull(result.obfuscationResult(),
        "Obfuscation analysis should have run");
  }
}
