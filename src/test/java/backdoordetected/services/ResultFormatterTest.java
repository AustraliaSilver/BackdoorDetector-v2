package backdoordetected.services;

import static org.junit.jupiter.api.Assertions.*;

import backdoordetected.detection.LMXBackdoorDetector;
import backdoordetected.models.ComprehensiveAnalysisResult;
import backdoordetected.models.ObfuscationResult;
import backdoordetected.models.PluginAnalysisResult;
import backdoordetected.models.SootAnalysisResult;
import backdoordetected.models.TaintFlow;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class ResultFormatterTest {

  private ResultFormatter formatter;

  @BeforeEach
  void setUp() {
    formatter = new ResultFormatter();
  }

  private LMXBackdoorDetector.BackdoorScanResult noBackdoor() {
    return new LMXBackdoorDetector.BackdoorScanResult();
  }

  private LMXBackdoorDetector.BackdoorScanResult lmxBackdoor() {
    LMXBackdoorDetector.BackdoorScanResult r = new LMXBackdoorDetector.BackdoorScanResult();
    r.hasLMXBackdoor = true;
    r.findings.add("L.M.X detected");
    return r;
  }

  @Test
  void emptyResultContainsCleanReport() {
    ComprehensiveAnalysisResult result = new ComprehensiveAnalysisResult(
        Map.of(), List.of(), noBackdoor(), "", List.of(), "", Map.of());
    String output = formatter.formatResult(result);
    assertTrue(output.contains("No Known Hardcoded Backdoor Signatures"));
    assertTrue(output.contains("Overall Malicious:** NO"));
    assertTrue(output.contains("Analysis Report"));
  }

  @Test
  void knownBackdoorMarkedAsYes() {
    ComprehensiveAnalysisResult result = new ComprehensiveAnalysisResult(
        Map.of(), List.of(), lmxBackdoor(), "", List.of(), "", Map.of());
    String output = formatter.formatResult(result);
    assertTrue(output.contains("Known Backdoor Detected"));
    assertTrue(output.contains("Malicious:** YES"));
    assertTrue(output.contains("Confidence:** 100%"));
    assertTrue(output.contains("Severity:** CRITICAL"));
    assertTrue(output.contains("L.M.X backdoor signature"));
  }

  @Test
  void bytecodeFindingsAreIncluded() {
    ComprehensiveAnalysisResult result = new ComprehensiveAnalysisResult(
        Map.of(Path.of("BYTECODE_ANALYSIS"),
            List.of("CRITICAL: Suspicious bytecode in class Evil")),
        List.of(), noBackdoor(), "", List.of(), "", Map.of());
    String output = formatter.formatResult(result);
    assertTrue(output.contains("Bytecode Analysis"));
    assertTrue(output.contains("CRITICAL: Suspicious bytecode"));
  }

  @Test
  void sootFindingsAreIncluded() {
    ComprehensiveAnalysisResult result = new ComprehensiveAnalysisResult(
        Map.of(Path.of("SOOT_ANALYSIS"),
            List.of("Taint flow from source to Runtime.exec")),
        List.of(), noBackdoor(), "", List.of(), "", Map.of());
    String output = formatter.formatResult(result);
    assertTrue(output.contains("Soot Taint Analysis"));
    assertTrue(output.contains("Taint flow from source"));
  }

  @Test
  void pluginAnalysisResultsAreIncluded() {
    Map<String, PluginAnalysisResult> pluginResults = new HashMap<>();
    Map<String, List<String>> findings = new HashMap<>();
    findings.put("test_key", List.of("Finding detail"));
    SootAnalysisResult sootResult = new SootAnalysisResult(
        "SootAnalyzer", findings, false, false, List.of(), List.of());
    pluginResults.put("soot", sootResult);

    ComprehensiveAnalysisResult result = new ComprehensiveAnalysisResult(
        Map.of(), List.of(), noBackdoor(), "", List.of(), "", pluginResults);
    String output = formatter.formatResult(result);
    assertTrue(output.contains("SootAnalyzer"));
    assertTrue(output.contains("OK"));
  }

  @Test
  void obfuscationWarningIsNotDirectlyInFormatter() {
    Map<String, PluginAnalysisResult> pluginResults = new HashMap<>();
    ObfuscationResult obfResult = new ObfuscationResult(
        "ObfuscationAnalyzer", Map.of(), true, false, 90,
        List.of("Heavy obfuscation"), true);
    pluginResults.put("ObfuscationAnalyzer", obfResult);

    ComprehensiveAnalysisResult result = new ComprehensiveAnalysisResult(
        Map.of(), List.of(), noBackdoor(), "", List.of(), "", pluginResults);
    String output = formatter.formatResult(result);
    assertTrue(output.contains("ObfuscationAnalyzer"));
  }

  @Test
  void highSeverityResultShowsHighlyLikely() {
    ComprehensiveAnalysisResult result = new ComprehensiveAnalysisResult(
        Map.of(Path.of("test.java"), List.of("CRITICAL: RCE")),
        List.of(), noBackdoor(), "", List.of(), "", Map.of());
    String output = formatter.formatResult(result);
    assertTrue(output.contains("Overall Malicious:** HIGHLY LIKELY"));
    assertTrue(output.contains("Overall Confidence:** HIGH"));
    assertTrue(output.contains("Overall Severity:** CRITICAL/HIGH"));
  }

  @Test
  void noFindingsShowsNoAndMedium() {
    ComprehensiveAnalysisResult result = new ComprehensiveAnalysisResult(
        Map.of(), List.of(), noBackdoor(), "", List.of(), "", Map.of());
    String output = formatter.formatResult(result);
    assertTrue(output.contains("Overall Malicious:** NO"));
    assertTrue(output.contains("Overall Severity:** NONE"));
  }
}
