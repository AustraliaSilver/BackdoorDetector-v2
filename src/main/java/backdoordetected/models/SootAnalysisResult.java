package backdoordetected.models;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class SootAnalysisResult extends PluginAnalysisResult {
  private final List<TaintFlow> taintFlows;
  private final List<String> errors;

  public SootAnalysisResult(
      String analyzerName,
      Map<String, List<String>> genericFindings,
      boolean hasHighSeverity,
      boolean hasLowSeverity,
      List<TaintFlow> taintFlows,
      List<String> errors) {
    super(analyzerName, genericFindings, hasHighSeverity, hasLowSeverity);
    this.taintFlows = taintFlows;
    this.errors = errors;
  }

  public static SootAnalysisResult empty(String analyzerName) {
    return new SootAnalysisResult(
        analyzerName, new HashMap<>(), false, false, List.of(), List.of());
  }

  public static SootAnalysisResult withErrors(String analyzerName, List<String> errors) {
    Map<String, List<String>> genericFindings = new HashMap<>();
    genericFindings.put("errors", new ArrayList<>(errors));
    return new SootAnalysisResult(analyzerName, genericFindings, false, false, List.of(), errors);
  }

  public List<TaintFlow> taintFlows() {
    return taintFlows;
  }

  public List<String> errors() {
    return errors;
  }

  @Override
  public boolean hasHighSeverityFindings() {
    return taintFlows.stream().anyMatch(flow -> "CRITICAL".equals(flow.severity()));
  }

  @Override
  public boolean hasAnyFindings() {
    return !taintFlows.isEmpty() || !errors.isEmpty() || super.hasAnyFindings();
  }

  public boolean hasFindings() {
    return hasAnyFindings();
  }

  public List<String> findings() {
    List<String> allFindings = new ArrayList<>();
    for (TaintFlow flow : taintFlows) {
      allFindings.add(flow.toString());
    }
    allFindings.addAll(errors);
    return allFindings;
  }
}
