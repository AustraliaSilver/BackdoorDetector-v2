package backdoordetected.models;

import com.microsoft.z3.Status;
import java.util.Collections;
import java.util.List;
import java.util.Map;

public record Z3Result(
    Status status,
    String explanation,
    Map<String, String> model,
    List<Map<String, String>> allPayloads,
    String payloadType,
    int confidence) {

  public boolean isBackdoorConfirmed() {
    return status == Status.SATISFIABLE;
  }

  public static Z3Result confirmed(String explanation, Map<String, String> model) {
    return new Z3Result(Status.SATISFIABLE, explanation, model, List.of(model), "unknown", 90);
  }

  public static Z3Result confirmed(
      String explanation, Map<String, String> model, List<Map<String, String>> allPayloads) {
    return new Z3Result(Status.SATISFIABLE, explanation, model, allPayloads, "unknown", 90);
  }

  public static Z3Result unreachable(String explanation) {
    return new Z3Result(
        Status.UNSATISFIABLE,
        explanation,
        Collections.emptyMap(),
        Collections.emptyList(),
        "unreachable",
        0);
  }

  public static Z3Result unknown(String explanation) {
    return new Z3Result(
        Status.UNKNOWN, explanation, Collections.emptyMap(), Collections.emptyList(), "unknown", 0);
  }

  @Override
  public String toString() {
    if (isBackdoorConfirmed()) {
      StringBuilder sb = new StringBuilder();
      sb.append(
          String.format("BACKDOOR CONFIRMED (Confidence: %d%%): %s%n", confidence, explanation));
      sb.append(String.format("Payload Type: %s%n", payloadType));
      sb.append(String.format("Primary PoC: %s%n", model));
      if (allPayloads.size() > 1) {
        sb.append(String.format("Alternative PoCs (%d):%n", allPayloads.size() - 1));
        for (int i = 1; i < allPayloads.size(); i++) {
          sb.append(String.format("  %d. %s%n", i, allPayloads.get(i)));
        }
      }
      return sb.toString();
    } else {
      return String.format("%s: %s", status, explanation);
    }
  }
}
