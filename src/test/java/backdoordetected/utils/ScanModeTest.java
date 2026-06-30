package backdoordetected.utils;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

class ScanModeTest {

  @Test
  void aiModesRequireApiKey() {
    assertTrue(ScanMode.AI_MODERN.requiresApiKey());
    assertTrue(ScanMode.AI_BACKDOOR_FOCUS.requiresApiKey());
  }

  @Test
  void nonAiModesDoNotRequireApiKey() {
    assertFalse(ScanMode.MODERN.requiresApiKey());
    assertFalse(ScanMode.BYTECODE.requiresApiKey());
    assertFalse(ScanMode.SANDBOX.requiresApiKey());
    assertFalse(ScanMode.DATA_FLOW.requiresApiKey());
    assertFalse(ScanMode.DEPENDENCY.requiresApiKey());
    assertFalse(ScanMode.SYMBOLIC.requiresApiKey());
  }

  @Test
  void aiModeRequiresApiKey() {
    assertTrue(ScanMode.AI.requiresApiKey());
  }

  @Test
  void fastModesIncludeModernBytecodeSandboxDependency() {
    assertTrue(ScanMode.MODERN.isFastMode());
    assertTrue(ScanMode.BYTECODE.isFastMode());
    assertTrue(ScanMode.SANDBOX.isFastMode());
    assertTrue(ScanMode.DEPENDENCY.isFastMode());
  }

  @Test
  void thoroughModesAreNotFast() {
    assertFalse(ScanMode.DATA_FLOW.isFastMode());
    assertFalse(ScanMode.SYMBOLIC.isFastMode());
  }

  @Test
  void aiModesIncludeMixed() {
    assertTrue(ScanMode.AI_MODERN.isFastMode());
    assertTrue(ScanMode.AI_BACKDOOR_FOCUS.isFastMode());
    assertFalse(ScanMode.AI.isFastMode());
  }

  @Test
  void getRecommendedReturnsAiModernWithApiKey() {
    assertEquals(ScanMode.AI_MODERN, ScanMode.getRecommendedMode(true, false));
  }

  @Test
  void getRecommendedReturnsModernForFastWithApiKey() {
    assertEquals(ScanMode.MODERN, ScanMode.getRecommendedMode(true, true));
  }

  @Test
  void getRecommendedReturnsDataFlowWithoutApiKey() {
    assertEquals(ScanMode.DATA_FLOW, ScanMode.getRecommendedMode(false, false));
  }

  @Test
  void getRecommendedReturnsModernWithoutApiKeyAndFast() {
    assertEquals(ScanMode.MODERN, ScanMode.getRecommendedMode(false, true));
  }

  @Test
  void descriptionIsNotEmpty() {
    for (ScanMode mode : ScanMode.values()) {
      assertNotNull(mode.getDescription());
      assertFalse(mode.getDescription().isEmpty());
    }
  }

  @Test
  void printAllModesDoesNotThrow() {
    assertDoesNotThrow(ScanMode::printAllModes);
  }

  @Test
  void valueOfIsCaseSensitive() {
    assertEquals(ScanMode.AI_MODERN, ScanMode.valueOf("AI_MODERN"));
  }
}
