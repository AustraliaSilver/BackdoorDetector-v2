package backdoordetected.detection;

import static org.junit.jupiter.api.Assertions.*;

import backdoordetected.models.TaintFlow;
import backdoordetected.models.Z3Result;
import com.microsoft.z3.Status;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class TaintConstraintGeneratorTest {

  @Test
  void testZ3ResultEnhancement_Confirmed() {
    Map<String, String> model1 = Map.of("user_input_0", "admin");
    Map<String, String> model2 = Map.of("user_input_0", "test");

    Z3Result result = Z3Result.confirmed("Test backdoor", model1, List.of(model1, model2));

    assertTrue(result.isBackdoorConfirmed());
    assertEquals(Status.SATISFIABLE, result.status());
    assertEquals(2, result.allPayloads().size());
    assertEquals(90, result.confidence());
    assertEquals("unknown", result.payloadType());
  }

  @Test
  void testZ3ResultEnhancement_Unreachable() {
    Z3Result result = Z3Result.unreachable("Path not feasible");

    assertFalse(result.isBackdoorConfirmed());
    assertEquals(Status.UNSATISFIABLE, result.status());
    assertEquals(0, result.confidence());
    assertTrue(result.allPayloads().isEmpty());
  }

  @Test
  void testZ3ResultToString_MultiplePayloads() {
    Map<String, String> model1 = Map.of("user_input_0", "payload1");
    Map<String, String> model2 = Map.of("user_input_0", "payload2");
    Map<String, String> model3 = Map.of("user_input_0", "payload3");

    Z3Result result = Z3Result.confirmed("Multiple payloads test", model1, List.of(model1, model2, model3));

    String output = result.toString();

    assertTrue(output.contains("BACKDOOR CONFIRMED"));
    assertTrue(output.contains("Alternative PoCs"));
    assertTrue(output.contains("Confidence: 90%"));
  }

  @Test
  void testTaintProofFormatting() {
    TaintFlow flow = new TaintFlow("backdoor.execute", "Runtime.exec", List.of("backdoor.java:42"), "CRITICAL");

    TaintConstraintGenerator.TaintProof proof = new TaintConstraintGenerator.TaintProof(
        flow, true, "admin; whoami", "User input reaches dangerous sink");

    String formatted = proof.toFormattedString();

    assertTrue(formatted.contains("Z3 PROOF-OF-CONCEPT"));
    assertTrue(formatted.contains("Runtime.exec"));
    assertTrue(formatted.contains("CONFIRMED EXPLOITABLE"));
    assertTrue(formatted.contains("admin") || formatted.contains("whoami"));
  }

  @Test
  void testTaintProofFormatting_MultiplePayloads() {
    TaintFlow flow = new TaintFlow("backdoor.execute", "Runtime.exec", List.of("backdoor.java:42"), "CRITICAL");

    String multiPayload = "admin; whoami\nroot; id\ntest; curl";

    TaintConstraintGenerator.TaintProof proof = new TaintConstraintGenerator.TaintProof(
        flow, true, multiPayload, "Multiple PoC payloads generated");

    String formatted = proof.toFormattedString();

    assertTrue(formatted.contains("PROOF-OF-CONCEPT PAYLOAD"));
    assertTrue(formatted.contains("1."));
    assertTrue(formatted.contains("2."));
  }
}
