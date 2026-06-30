package backdoordetected.models;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class AnalysisResultTest {

  @Test
  void emptyResultHasNoFindings() {
    AnalysisResult result = new AnalysisResult("test", Map.of(), List.of());
    assertFalse(result.hasFindings());
  }

  @Test
  void nonEmptyFindingsHasFindings() {
    AnalysisResult result = new AnalysisResult(
        "test", Map.of(Path.of("f.java"), List.of("finding")), List.of());
    assertTrue(result.hasFindings());
  }

  @Test
  void nullFindingsHasNoFindings() {
    AnalysisResult result = new AnalysisResult("test", null, List.of());
    assertFalse(result.hasFindings());
  }

  @Test
  void analyzerNameIsPreserved() {
    AnalysisResult result = new AnalysisResult("MyAnalyzer", Map.of(), List.of());
    assertEquals("MyAnalyzer", result.analyzerName());
  }

  @Test
  void failedFilesArePreserved() {
    List<Path> failed = List.of(Path.of("broken.java"));
    AnalysisResult result = new AnalysisResult("test", Map.of(), failed);
    assertEquals(1, result.failedFiles().size());
    assertTrue(result.failedFiles().contains(Path.of("broken.java")));
  }
}
