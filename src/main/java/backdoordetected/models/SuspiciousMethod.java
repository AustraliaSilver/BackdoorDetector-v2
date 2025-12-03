package backdoordetected.models;

public record SuspiciousMethod(
    String className,
    String methodName,
    String methodSignature,
    String dangerousSink,
    int lineNumber,
    String severity) {

  public boolean requiresSymbolicAnalysis() {
    return "CRITICAL".equals(severity);
  }

  @Override
  public String toString() {
    return String.format("[%s] %s.%s -> %s", severity, className, methodName, dangerousSink);
  }
}
