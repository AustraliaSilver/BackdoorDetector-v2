package backdoordetected.models;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class SootAnalysisResultTest {

  @Test
  void emptyResultHasNoFindings() {
    SootAnalysisResult result = SootAnalysisResult.empty("test");
    assertFalse(result.hasFindings());
    assertFalse(result.hasHighSeverityFindings());
    assertFalse(result.hasAnyFindings());
    assertTrue(result.taintFlows().isEmpty());
    assertTrue(result.errors().isEmpty());
  }

  @Test
  void criticalTaintFlowIsHighSeverity() {
    List<TaintFlow> flows = List.of(
        new TaintFlow("source", "sink", List.of("file.java:10"), "CRITICAL"));
    SootAnalysisResult result = new SootAnalysisResult(
        "test", Map.of(), false, false, flows, List.of());
    assertTrue(result.hasFindings());
    assertTrue(result.hasHighSeverityFindings());
    assertTrue(result.hasAnyFindings());
  }

  @Test
  void lowSeverityTaintFlowIsNotHighSeverity() {
    List<TaintFlow> flows = List.of(
        new TaintFlow("source", "sink", List.of("file.java:10"), "LOW"));
    SootAnalysisResult result = new SootAnalysisResult(
        "test", Map.of(), false, false, flows, List.of());
    assertTrue(result.hasFindings());
    assertFalse(result.hasHighSeverityFindings());
  }

  @Test
  void withErrorsHasFindings() {
    SootAnalysisResult result = SootAnalysisResult.withErrors("test", List.of("Failed to analyze"));
    assertTrue(result.hasFindings());
    assertFalse(result.hasHighSeverityFindings());
    assertEquals(1, result.errors().size());
  }

  @Test
  void findingsIncludesTaintFlowsAndErrors() {
    List<TaintFlow> flows = List.of(
        new TaintFlow("src", "sink", List.of("A.java:1"), "HIGH"));
    SootAnalysisResult result = new SootAnalysisResult(
        "test", Map.of(), true, false, flows, List.of("error1"));
    List<String> allFindings = result.findings();
    assertTrue(allFindings.stream().anyMatch(f -> f.contains("src")));
    assertTrue(allFindings.contains("error1"));
  }
}
