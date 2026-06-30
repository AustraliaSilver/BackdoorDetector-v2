package backdoordetected.analyzers;

import static org.junit.jupiter.api.Assertions.*;

import backdoordetected.analyzers.CFGAnalyzer.InterproceduralCFG;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;

class CFGAnalyzerTest {

  private final CFGAnalyzer analyzer = new CFGAnalyzer();

  @Test
  void analyzeWithEmptyMethodProducesNoFindings() {
    MethodNode method = new MethodNode();
    method.instructions = new InsnList();
    method.name = "emptyMethod";

    Set<String> findings = new HashSet<>();
    analyzer.analyze(method, "TestClass", findings);
    assertTrue(findings.isEmpty());
  }

  @Test
  void analyzeWithLinearCodeProducesNoFindings() {
    MethodNode method = new MethodNode();
    method.instructions.add(new InsnNode(Opcodes.ICONST_0));
    method.instructions.add(new InsnNode(Opcodes.ICONST_1));
    method.instructions.add(new InsnNode(Opcodes.IADD));
    method.instructions.add(new InsnNode(Opcodes.IRETURN));
    method.name = "linearMethod";

    Set<String> findings = new HashSet<>();
    analyzer.analyze(method, "TestClass", findings);
    assertTrue(findings.stream().noneMatch(f -> f.contains("Unreachable code")));
  }

  @Test
  void analyzeWithDeadCodeAfterGotoDetectsUnreachable() {
    LabelNode target = new LabelNode();
    MethodNode method = new MethodNode();
    method.instructions.add(new JumpInsnNode(Opcodes.GOTO, target));
    method.instructions.add(new InsnNode(Opcodes.ICONST_1));
    method.instructions.add(new InsnNode(Opcodes.IRETURN));
    method.instructions.add(target);
    method.instructions.add(new InsnNode(Opcodes.ICONST_2));
    method.instructions.add(new InsnNode(Opcodes.IRETURN));
    method.name = "gotoMethod";

    Set<String> findings = new HashSet<>();
    analyzer.analyze(method, "TestClass", findings);
    boolean hasDeadCode = findings.stream().anyMatch(f -> f.contains("Unreachable code"));
    assertTrue(hasDeadCode);
  }

  @Test
  void analyzeWithConditionalJumpProducesNoDeadCode() {
    LabelNode target = new LabelNode();
    MethodNode method = new MethodNode();
    method.instructions.add(new InsnNode(Opcodes.ICONST_0));
    method.instructions.add(new JumpInsnNode(Opcodes.IFEQ, target));
    method.instructions.add(new InsnNode(Opcodes.ICONST_1));
    method.instructions.add(new InsnNode(Opcodes.IRETURN));
    method.instructions.add(target);
    method.instructions.add(new InsnNode(Opcodes.ICONST_2));
    method.instructions.add(new InsnNode(Opcodes.IRETURN));
    method.name = "ifMethod";

    Set<String> findings = new HashSet<>();
    analyzer.analyze(method, "TestClass", findings);
    assertFalse(findings.stream().anyMatch(f -> f.contains("Unreachable code")));
  }

  @Test
  void analyzeMethodClassNameAppearsInFindings() {
    MethodNode method = new MethodNode();
    method.name = "testMethod";
    Set<String> findings = new HashSet<>();
    LabelNode target = new LabelNode();
    method.instructions.add(new JumpInsnNode(Opcodes.GOTO, target));
    method.instructions.add(new InsnNode(Opcodes.ICONST_1));
    method.instructions.add(new InsnNode(Opcodes.IRETURN));
    method.instructions.add(target);
    method.instructions.add(new InsnNode(Opcodes.RETURN));

    analyzer.analyze(method, "com/example/MyClass", findings);
    assertFalse(findings.isEmpty());
    assertTrue(findings.stream().anyMatch(f -> f.contains("com.example.MyClass")
        || f.contains("com/example/MyClass")));
  }

  @Test
  void buildInterproceduralCFGWithSingleMethod() {
    MethodNode method = new MethodNode();
    method.instructions.add(new InsnNode(Opcodes.ICONST_0));
    method.instructions.add(new InsnNode(Opcodes.IRETURN));

    InterproceduralCFG ipcfg = analyzer.buildInterproceduralCFG(List.of(method));
    assertEquals(1, ipcfg.getMethods().size());
    assertNotNull(ipcfg.getCFG(method));
  }

  @Test
  void buildInterproceduralCFGWithMultipleMethods() {
    MethodNode method1 = new MethodNode();
    method1.instructions.add(new InsnNode(Opcodes.ICONST_0));
    method1.instructions.add(new InsnNode(Opcodes.IRETURN));

    MethodNode method2 = new MethodNode();
    method2.instructions.add(new MethodInsnNode(
        Opcodes.INVOKEVIRTUAL, "Foo", "bar", "()V", false));
    method2.instructions.add(new InsnNode(Opcodes.RETURN));

    InterproceduralCFG ipcfg = analyzer.buildInterproceduralCFG(List.of(method1, method2));
    assertEquals(2, ipcfg.getMethods().size());
    assertFalse(ipcfg.getCallSites().isEmpty());
  }

  @Test
  void analyzeWithTableSwitchDoesNotCrash() {
    LabelNode case1 = new LabelNode();
    LabelNode defaultTarget = new LabelNode();
    MethodNode method = new MethodNode();
    method.instructions.add(new InsnNode(Opcodes.ICONST_0));
    method.instructions.add(new TableSwitchInsnNode(0, 1, defaultTarget, case1));
    method.instructions.add(new InsnNode(Opcodes.IRETURN));
    method.instructions.add(defaultTarget);
    method.instructions.add(new InsnNode(Opcodes.IRETURN));
    method.instructions.add(case1);
    method.instructions.add(new InsnNode(Opcodes.ICONST_1));
    method.instructions.add(new InsnNode(Opcodes.IRETURN));
    method.name = "switchMethod";

    Set<String> findings = new HashSet<>();
    analyzer.analyze(method, "TestClass", findings);
    assertNotNull(findings);
  }

  @Test
  void analyzeWithLookupSwitchDoesNotCrash() {
    LabelNode case1 = new LabelNode();
    LabelNode defaultTarget = new LabelNode();
    MethodNode method = new MethodNode();
    method.instructions.add(new InsnNode(Opcodes.ICONST_0));
    method.instructions.add(new LookupSwitchInsnNode(defaultTarget, new int[]{1, 2}, new LabelNode[]{case1, defaultTarget}));
    method.instructions.add(new InsnNode(Opcodes.IRETURN));
    method.instructions.add(defaultTarget);
    method.instructions.add(new InsnNode(Opcodes.IRETURN));
    method.instructions.add(case1);
    method.instructions.add(new InsnNode(Opcodes.ICONST_1));
    method.instructions.add(new InsnNode(Opcodes.IRETURN));
    method.name = "lookupMethod";

    Set<String> findings = new HashSet<>();
    analyzer.analyze(method, "TestClass", findings);
    assertNotNull(findings);
  }
}
