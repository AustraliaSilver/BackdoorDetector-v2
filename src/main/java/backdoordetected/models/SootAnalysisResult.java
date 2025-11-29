package backdoordetected.models;

import java.util.List;


public record SootAnalysisResult(
        List<TaintFlow> taintFlows,
        List<String> findings,
        List<String> errors) {

    
    public static SootAnalysisResult empty() {
        return new SootAnalysisResult(List.of(), List.of(), List.of());
    }

    
    public static SootAnalysisResult withErrors(List<String> errors) {
        return new SootAnalysisResult(List.of(), List.of(), errors);
    }

    
    public boolean hasFindings() {
        return !taintFlows.isEmpty() || !findings.isEmpty();
    }

    
    public boolean hasCriticalFindings() {
        return taintFlows.stream()
                .anyMatch(flow -> "CRITICAL".equals(flow.severity()));
    }
}
