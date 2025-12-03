package backdoordetected.utils;

public class AnalysisConfig {
    private int maxSymbolicExecutionDepth = 10;
    private int maxPathsToExplore = 100;
    private boolean enableStateForking = true;
    private boolean enableSymbolicExecution = true;
    private boolean enableConstraintCaching = true;
    private boolean enableConstraintSimplification = true;
    private int constraintSolverTimeout = 5000;
    private boolean enableIncrementalSolving = true;
    private boolean enableInterproceduralAnalysis = true;
    private int maxCallDepth = 5;
    private boolean enableBackwardSlicing = true;
    private boolean enableForwardSlicing = true;
    private boolean enablePDGAnalysis = true;
    private boolean enableParallelAnalysis = true;
    private int analysisThreads = 0;

    public int getMaxSymbolicExecutionDepth() {
        return maxSymbolicExecutionDepth;
    }

    public void setMaxSymbolicExecutionDepth(int maxSymbolicExecutionDepth) {
        this.maxSymbolicExecutionDepth = maxSymbolicExecutionDepth;
    }

    public int getMaxPathsToExplore() {
        return maxPathsToExplore;
    }

    public void setMaxPathsToExplore(int maxPathsToExplore) {
        this.maxPathsToExplore = maxPathsToExplore;
    }

    public boolean isEnableStateForking() {
        return enableStateForking;
    }

    public void setEnableStateForking(boolean enableStateForking) {
        this.enableStateForking = enableStateForking;
    }

    public boolean isEnableSymbolicExecution() {
        return enableSymbolicExecution;
    }

    public void setEnableSymbolicExecution(boolean enableSymbolicExecution) {
        this.enableSymbolicExecution = enableSymbolicExecution;
    }

    public boolean isEnableConstraintCaching() {
        return enableConstraintCaching;
    }

    public void setEnableConstraintCaching(boolean enableConstraintCaching) {
        this.enableConstraintCaching = enableConstraintCaching;
    }

    public boolean isEnableConstraintSimplification() {
        return enableConstraintSimplification;
    }

    public void setEnableConstraintSimplification(boolean enableConstraintSimplification) {
        this.enableConstraintSimplification = enableConstraintSimplification;
    }

    public int getConstraintSolverTimeout() {
        return constraintSolverTimeout;
    }

    public void setConstraintSolverTimeout(int constraintSolverTimeout) {
        this.constraintSolverTimeout = constraintSolverTimeout;
    }

    public boolean isEnableIncrementalSolving() {
        return enableIncrementalSolving;
    }

    public void setEnableIncrementalSolving(boolean enableIncrementalSolving) {
        this.enableIncrementalSolving = enableIncrementalSolving;
    }

    public boolean isEnableInterproceduralAnalysis() {
        return enableInterproceduralAnalysis;
    }

    public void setEnableInterproceduralAnalysis(boolean enableInterproceduralAnalysis) {
        this.enableInterproceduralAnalysis = enableInterproceduralAnalysis;
    }

    public int getMaxCallDepth() {
        return maxCallDepth;
    }

    public void setMaxCallDepth(int maxCallDepth) {
        this.maxCallDepth = maxCallDepth;
    }

    public boolean isEnableBackwardSlicing() {
        return enableBackwardSlicing;
    }

    public void setEnableBackwardSlicing(boolean enableBackwardSlicing) {
        this.enableBackwardSlicing = enableBackwardSlicing;
    }

    public boolean isEnableForwardSlicing() {
        return enableForwardSlicing;
    }

    public void setEnableForwardSlicing(boolean enableForwardSlicing) {
        this.enableForwardSlicing = enableForwardSlicing;
    }

    public boolean isEnablePDGAnalysis() {
        return enablePDGAnalysis;
    }

    public void setEnablePDGAnalysis(boolean enablePDGAnalysis) {
        this.enablePDGAnalysis = enablePDGAnalysis;
    }

    public boolean isEnableParallelAnalysis() {
        return enableParallelAnalysis;
    }

    public void setEnableParallelAnalysis(boolean enableParallelAnalysis) {
        this.enableParallelAnalysis = enableParallelAnalysis;
    }

    public int getAnalysisThreads() {
        return analysisThreads == 0 ? Runtime.getRuntime().availableProcessors() : analysisThreads;
    }

    public void setAnalysisThreads(int analysisThreads) {
        this.analysisThreads = analysisThreads;
    }

    public static AnalysisConfig createDefault() {
        return new AnalysisConfig();
    }

    public static AnalysisConfig createFast() {
        AnalysisConfig config = new AnalysisConfig();
        config.setMaxSymbolicExecutionDepth(5);
        config.setMaxPathsToExplore(50);
        config.setMaxCallDepth(3);
        config.setEnableSymbolicExecution(false);
        return config;
    }

    public static AnalysisConfig createThorough() {
        AnalysisConfig config = new AnalysisConfig();
        config.setMaxSymbolicExecutionDepth(20);
        config.setMaxPathsToExplore(200);
        config.setMaxCallDepth(10);
        return config;
    }

    @Override
    public String toString() {
        return String.format(
                "AnalysisConfig[symbolic_depth=%d, max_paths=%d, interprocedural=%s, pdg=%s]",
                maxSymbolicExecutionDepth,
                maxPathsToExplore,
                enableInterproceduralAnalysis,
                enablePDGAnalysis);
    }
}
