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

class AdvancedAntiVPNIntegrationTest {

  private static final Path JAR = Path.of("temp", "AdvancedAntiVPN-2.31.7.jar");
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
        JAR, ScanMode.BYTECODE, "advancedantivpn-test");

    assertNotNull(result, "Analysis result should not be null");
    assertNotNull(result.eventFindings(), "Event findings should not be null");

    assertFalse(result.hasKnownBackdoor(),
        "AdvancedAntiVPN should NOT be flagged as a known backdoor");

    Map<Path, List<String>> findings = result.eventFindings();
    List<String> bcFindings = findings.get(Path.of("BYTECODE_ANALYSIS"));

    assertNotNull(bcFindings, "Should have BYTECODE_ANALYSIS findings");
    assertFalse(bcFindings.isEmpty(),
        "Bytecode analysis should detect patterns in AdvancedAntiVPN");

    String all = String.join(" ", bcFindings);

    // Core anti-VPN functionality: dispatchCommand kicks VPN users
    assertTrue(all.contains("dispatchCommand"),
        "Should flag dispatchCommand (core VPN-kick functionality)");

    // Class.forName loads SQLite JDBC driver
    assertTrue(all.contains("Class.forName"),
        "Should detect Class.forName calls (SQLite driver load)");

    // URL.openConnection for VPN API services and bStats
    assertTrue(all.contains("URL.openConnection") || all.contains(".openConnection"),
        "Should flag URL connections (VPN API + bStats)");

    // Obfuscation analysis should have run
    assertNotNull(result.obfuscationResult(),
        "Obfuscation analysis should have run");
  }
}
