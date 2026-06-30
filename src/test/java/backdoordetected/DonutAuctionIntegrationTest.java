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

class DonutAuctionIntegrationTest {

  private static final Path DONUTAUCTION_JAR = Path.of("temp", "DonutAuction-1.6 2.jar");
  private static AnalysisCoordinator coordinator;

  @BeforeAll
  static void setUp() {
    coordinator = new AnalysisCoordinator();
  }

  @Test
  @Timeout(300)
  void scanIdentifiesFindingsButNotKnownBackdoor() throws Exception {
    assertTrue(Files.exists(DONUTAUCTION_JAR),
        "DonutAuction JAR must exist at: " + DONUTAUCTION_JAR);

    ComprehensiveAnalysisResult result = coordinator.analyze(
        DONUTAUCTION_JAR, ScanMode.BYTECODE, "donut-test");

    assertNotNull(result, "Analysis result should not be null");
    assertNotNull(result.eventFindings(), "Event findings should not be null");

    // DonutAuction is a legitimate premium auction plugin — NOT a known backdoor
    assertFalse(result.hasKnownBackdoor(),
        "DonutAuction should NOT be flagged as a known backdoor");

    Map<Path, List<String>> findings = result.eventFindings();
    List<String> bcFindings = findings.get(Path.of("BYTECODE_ANALYSIS"));

    assertNotNull(bcFindings, "Should have BYTECODE_ANALYSIS findings from bytecode scan");
    assertFalse(bcFindings.isEmpty(),
        "Bytecode analysis should detect suspicious patterns in DonutAuction");

    String all = String.join(" ", bcFindings);

    // LicenseManager has an IP address (license validation server, not a C2)
    assertTrue(all.contains("154.43.52.66"),
        "Should flag IP address in LicenseManager");
    assertTrue(all.contains("LicenseManager"),
        "Should flag LicenseManager class");

    // Class.forName in Auktionshaus.onEnable (Folia detection, NOT a backdoor)
    assertTrue(all.contains("Class.forName"),
        "Should detect Class.forName calls");

    // URL.openConnection in LicenseManager for license validation
    assertTrue(all.contains("URL.openConnection"),
        "Should flag URL.openConnection in LicenseManager");

    // Auktionshaus is the main plugin class
    assertTrue(all.contains("Auktionshaus") || all.contains("onEnable"),
        "Should reference Auktionshaus or onEnable");

    // Verify the scan was comprehensive — should have ObfuscationResult too
    assertNotNull(result.obfuscationResult(),
        "Obfuscation analysis should have run");
  }
}
