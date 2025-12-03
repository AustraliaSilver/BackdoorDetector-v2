package backdoordetected.models;

public record TaintFlow(String source, String sink, java.util.List<String> path, String severity) {

  public String toFormattedString() {
    StringBuilder sb = new StringBuilder();
    sb.append("[").append(severity).append("] Taint Flow Detected\n");
    sb.append("  Source: ").append(source).append("\n");
    sb.append("  Sink: ").append(sink).append("\n");
    if (!path.isEmpty()) {
      sb.append("  Path:\n");
      for (String step : path) {
        sb.append("    → ").append(step).append("\n");
      }
    }
    return sb.toString();
  }
}
