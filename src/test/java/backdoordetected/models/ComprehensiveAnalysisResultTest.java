package backdoordetected.models;

import static org.junit.jupiter.api.Assertions.*;

import backdoordetected.detection.LMXBackdoorDetector;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class ComprehensiveAnalysisResultTest {

  private static LMXBackdoorDetector.BackdoorScanResult noBackdoor() {
    return new LMXBackdoorDetector.BackdoorScanResult();
  }

  private static LMXBackdoorDetector.BackdoorScanResult lmxBackdoor() {
    LMXBackdoorDetector.BackdoorScanResult r = new LMXBackdoorDetector.BackdoorScanResult();
    r.hasLMXBackdoor = true;
    r.findings.add("L.M.X detected");
    return r;
  }

  private static LMXBackdoorDetector.BackdoorScanResult openEctasyBackdoor() {
    LMXBackdoorDetector.BackdoorScanResult r = new LMXBackdoorDetector.BackdoorScanResult();
    r.hasOpenEctasy = true;
    r.findings.add("OpenEctasy detected");
    return r;
  }

  private ComprehensiveAnalysisResult makeResult(
      Map<Path, List<String>> eventFindings,
      LMXBackdoorDetector.BackdoorScanResult backdoorScan,
      Map<String, PluginAnalysisResult> pluginResults) {
    return new ComprehensiveAnalysisResult(
        eventFindings, List.of(), backdoorScan, "", List.of(), "", pluginResults);
  }

  @Test
  void emptyResultHasNoFindings() {
    ComprehensiveAnalysisResult result = makeResult(Map.of(), noBackdoor(), Map.of());
    assertFalse(result.hasFindings());
    assertFalse(result.hasHighSeverityFindings());
    assertFalse(result.hasKnownBackdoor());
  }

  @Test
  void lmxBackdoorIsDetected() {
    ComprehensiveAnalysisResult result = makeResult(Map.of(), lmxBackdoor(), Map.of());
    assertTrue(result.hasFindings());
    assertTrue(result.hasKnownBackdoor());
    assertTrue(result.hasHighSeverityFindings());
  }

  @Test
  void openEctasyBackdoorIsDetected() {
    ComprehensiveAnalysisResult result = makeResult(Map.of(), openEctasyBackdoor(), Map.of());
    assertTrue(result.hasFindings());
    assertTrue(result.hasKnownBackdoor());
    assertTrue(result.hasHighSeverityFindings());
  }

  @Test
  void criticalEventFindingsTriggersHighSeverity() {
    ComprehensiveAnalysisResult result = makeResult(
        Map.of(Path.of("test.java"), List.of("CRITICAL: Remote code execution")),
        noBackdoor(),
        Map.of());
    assertTrue(result.hasFindings());
    assertTrue(result.hasHighSeverityFindings());
  }

  @Test
  void highEventFindingsTriggersHighSeverity() {
    ComprehensiveAnalysisResult result = makeResult(
        Map.of(Path.of("test.java"), List.of("HIGH: Privilege escalation")),
        noBackdoor(),
        Map.of());
    assertTrue(result.hasHighSeverityFindings());
  }

  @Test
  void mediumEventFindingsTriggersHighSeverity() {
    ComprehensiveAnalysisResult result = makeResult(
        Map.of(Path.of("test.java"), List.of("MEDIUM: Suspicious config")),
        noBackdoor(),
        Map.of());
    assertTrue(result.hasHighSeverityFindings());
  }

  @Test
  void lowFindingsOnlyDontTriggerHighSeverity() {
    ComprehensiveAnalysisResult result = makeResult(
        Map.of(Path.of("test.java"), List.of("LOW: Minor issue")),
        noBackdoor(),
        Map.of());
    assertTrue(result.hasFindings());
    assertFalse(result.hasHighSeverityFindings());
  }

  @Test
  void pluginAnalysisResultsContributeToFindings() {
    Map<String, PluginAnalysisResult> pluginResults = new HashMap<>();
    pluginResults.put("sootTaintAnalyzer", SootAnalysisResult.empty("sootTaintAnalyzer"));
    ComprehensiveAnalysisResult result = makeResult(Map.of(), noBackdoor(), pluginResults);
    assertFalse(result.hasFindings());
    assertFalse(result.hasHighSeverityFindings());
  }

  @Test
  void sootResultWithCriticalFlowsIsHighSeverity() {
    Map<String, PluginAnalysisResult> pluginResults = new HashMap<>();
    List<TaintFlow> flows = List.of(
        new TaintFlow("source", "sink", List.of("test.java:42"), "CRITICAL"));
    SootAnalysisResult sootResult = new SootAnalysisResult(
        "sootTaintAnalyzer", Map.of(), true, false, flows, List.of());
    pluginResults.put("sootTaintAnalyzer", sootResult);
    ComprehensiveAnalysisResult result = makeResult(Map.of(), noBackdoor(), pluginResults);
    assertTrue(result.hasFindings());
    assertTrue(result.hasHighSeverityFindings());
  }

  @Test
  void getAnalyzerResultReturnsCorrectType() {
    Map<String, PluginAnalysisResult> pluginResults = new HashMap<>();
    SootAnalysisResult sootResult = SootAnalysisResult.empty("sootTaintAnalyzer");
    pluginResults.put("sootTaintAnalyzer", sootResult);
    ComprehensiveAnalysisResult result = makeResult(Map.of(), noBackdoor(), pluginResults);

    Optional<SootAnalysisResult> found = result.getAnalyzerResult("sootTaintAnalyzer", SootAnalysisResult.class);
    assertTrue(found.isPresent());
    assertEquals("sootTaintAnalyzer", found.get().getAnalyzerName());
  }

  @Test
  void getAnalyzerResultReturnsEmptyForWrongType() {
    Map<String, PluginAnalysisResult> pluginResults = new HashMap<>();
    SootAnalysisResult sootResult = SootAnalysisResult.empty("sootTaintAnalyzer");
    pluginResults.put("sootTaintAnalyzer", sootResult);
    ComprehensiveAnalysisResult result = makeResult(Map.of(), noBackdoor(), pluginResults);

    Optional<ObfuscationResult> found = result.getAnalyzerResult("sootTaintAnalyzer", ObfuscationResult.class);
    assertFalse(found.isPresent());
  }

  @Test
  void getAnalyzerResultReturnsEmptyForMissingName() {
    ComprehensiveAnalysisResult result = makeResult(Map.of(), noBackdoor(), Map.of());
    Optional<SootAnalysisResult> found = result.getAnalyzerResult("nonexistent", SootAnalysisResult.class);
    assertFalse(found.isPresent());
  }

  @Test
  void obfuscationResultReturnsEmptyWhenMissing() {
    ComprehensiveAnalysisResult result = makeResult(Map.of(), noBackdoor(), Map.of());
    ObfuscationResult obf = result.obfuscationResult();
    assertFalse(obf.isHeavilyObfuscated());
    assertEquals(0, obf.score());
    assertEquals("ObfuscationAnalyzer", obf.getAnalyzerName());
  }

  @Test
  void obfuscationResultReturnsActualResult() {
    Map<String, PluginAnalysisResult> pluginResults = new HashMap<>();
    ObfuscationResult obfResult = new ObfuscationResult(
        "ObfuscationAnalyzer", Map.of(), true, false, 85,
        List.of("Heavy obfuscation detected"), true);
    pluginResults.put("ObfuscationAnalyzer", obfResult);
    ComprehensiveAnalysisResult result = makeResult(Map.of(), noBackdoor(), pluginResults);

    ObfuscationResult obf = result.obfuscationResult();
    assertTrue(obf.isHeavilyObfuscated());
    assertEquals(85, obf.score());
  }

  @Test
  void suspiciousFilesParamIsPreserved() {
    List<Path> suspiciousFiles = List.of(Path.of("evil.java"), Path.of("backdoor.java"));
    ComprehensiveAnalysisResult result = new ComprehensiveAnalysisResult(
        Map.of(), List.of(), noBackdoor(), "", suspiciousFiles, "", Map.of());
    assertEquals(2, result.suspiciousFiles().size());
    assertTrue(result.suspiciousFiles().contains(Path.of("evil.java")));
  }

  @Test
  void directoryTreeParamIsPreserved() {
    String tree = "└─ src/\n  └─ main/\n";
    ComprehensiveAnalysisResult result = new ComprehensiveAnalysisResult(
        Map.of(), List.of(), noBackdoor(), tree, List.of(), "", Map.of());
    assertEquals(tree, result.directoryTree());
  }

  @Test
  void combinedCodeParamIsPreserved() {
    String code = "public class Test {}";
    ComprehensiveAnalysisResult result = new ComprehensiveAnalysisResult(
        Map.of(), List.of(), noBackdoor(), "", List.of(), code, Map.of());
    assertEquals(code, result.combinedCode());
  }

  @Test
  void failedFilesParamIsPreserved() {
    List<Path> failedFiles = List.of(Path.of("broken.java"));
    ComprehensiveAnalysisResult result = new ComprehensiveAnalysisResult(
        Map.of(), failedFiles, noBackdoor(), "", List.of(), "", Map.of());
    assertEquals(1, result.failedFiles().size());
    assertTrue(result.failedFiles().contains(Path.of("broken.java")));
  }
}
