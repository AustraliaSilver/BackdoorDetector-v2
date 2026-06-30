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

class BotSentryIntegrationTest {

  private static final Path JAR = Path.of("temp", "BotSentry-9.8-THANATOS-SpigotMC.jar");
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
        JAR, ScanMode.BYTECODE, "botsentry-test");

    assertNotNull(result, "Analysis result should not be null");
    assertNotNull(result.eventFindings(), "Event findings should not be null");

    assertFalse(result.hasKnownBackdoor(),
        "BotSentry should NOT be flagged as a known backdoor");

    Map<Path, List<String>> findings = result.eventFindings();
    List<String> bcFindings = findings.get(Path.of("BYTECODE_ANALYSIS"));

    assertNotNull(bcFindings, "Should have BYTECODE_ANALYSIS findings");
    assertFalse(bcFindings.isEmpty(),
        "Bytecode analysis should detect patterns in BotSentry");

    String all = String.join(" ", bcFindings);

    // Class.forName used for detection logic
    assertTrue(all.contains("Class.forName"),
        "Should detect Class.forName calls");

    // Obfuscation analysis should have run
    assertNotNull(result.obfuscationResult(),
        "Obfuscation analysis should have run");
  }
}
