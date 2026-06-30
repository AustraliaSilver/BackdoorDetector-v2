package backdoordetected.services;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import org.junit.jupiter.api.Test;

class AIPromptBuilderTest {

  @Test
  void buildWithDefaults() {
    AIPromptBuilder builder = new AIPromptBuilder();
    String result = builder.build();
    assertNotNull(result);
    assertTrue(result.contains("N/A"));
    assertTrue(result.contains("INITIAL FINDINGS:"));
  }

  @Test
  void buildWithSuspiciousFiles() {
    String result = new AIPromptBuilder()
        .withSuspiciousFiles(List.of("evil.java", "backdoor.class"))
        .build();
    assertTrue(result.contains("evil.java"));
    assertTrue(result.contains("backdoor.class"));
  }

  @Test
  void buildWithFindings() {
    String result = new AIPromptBuilder()
        .withFindings("CRITICAL: Remote code execution detected")
        .build();
    assertTrue(result.contains("CRITICAL: Remote code execution detected"));
  }

  @Test
  void buildWithCode() {
    String result = new AIPromptBuilder()
        .withCode("public class Test {}")
        .build();
    assertTrue(result.contains("public class Test {}"));
  }

  @Test
  void buildWithDirectoryTree() {
    String result = new AIPromptBuilder()
        .withDirectoryTree("└─ src/\n  └─ main/\n")
        .build();
    assertTrue(result.contains("Directory Tree:"));
    assertTrue(result.contains("src/"));
  }

  @Test
  void buildWithKnownBackdoor() {
    String result = new AIPromptBuilder()
        .withKnownBackdoorDetected(true)
        .build();
    assertNotNull(result);
  }

  @Test
  void builderReturnsItselfForChaining() {
    AIPromptBuilder builder = new AIPromptBuilder();
    assertSame(builder, builder.withSuspiciousFiles(null));
    assertSame(builder, builder.withFindings(null));
    assertSame(builder, builder.withCode(null));
    assertSame(builder, builder.withDirectoryTree(null));
    assertSame(builder, builder.withKnownBackdoorDetected(false));
  }

  @Test
  void nullListsHandledGracefully() {
    AIPromptBuilder builder = new AIPromptBuilder();
    builder.withSuspiciousFiles(null);
    String result = builder.build();
    assertTrue(result.contains("N/A"));
  }

  @Test
  void emptySuspiciousFilesShowsNA() {
    String result = new AIPromptBuilder()
        .withSuspiciousFiles(List.of())
        .build();
    assertTrue(result.contains("N/A"));
  }

}
