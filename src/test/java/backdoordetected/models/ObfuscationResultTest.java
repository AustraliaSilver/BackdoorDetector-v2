package backdoordetected.models;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class ObfuscationResultTest {

  @Test
  void emptyResultHasZeroScore() {
    ObfuscationResult result = ObfuscationResult.empty("test");
    assertEquals(0, result.score());
    assertFalse(result.isHeavilyObfuscated());
    assertTrue(result.warnings().isEmpty());
    assertFalse(result.hasAnyFindings());
  }

  @Test
  void highScoreIsHeavilyObfuscated() {
    ObfuscationResult result = new ObfuscationResult(
        "test", Map.of(), true, false, 85,
        List.of("Heavy obfuscation"), true);
    assertTrue(result.isHeavilyObfuscated());
    assertEquals(85, result.score());
    assertEquals(1, result.warnings().size());
  }

  @Test
  void lowScoreIsNotHeavilyObfuscated() {
    ObfuscationResult result = new ObfuscationResult(
        "test", Map.of(), false, false, 15,
        List.of("Mild obfuscation"), false);
    assertFalse(result.isHeavilyObfuscated());
    assertEquals(15, result.score());
  }

  @Test
  void analyzerNameIsPreserved() {
    ObfuscationResult result = ObfuscationResult.empty("MyAnalyzer");
    assertEquals("MyAnalyzer", result.getAnalyzerName());
  }
}
