package backdoordetected.detection;

import static org.junit.jupiter.api.Assertions.*;

import backdoordetected.detection.AbstractTaintInterpreter.AbstractState;
import backdoordetected.detection.AbstractTaintInterpreter.TaintState;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;

class AbstractTaintInterpreterTest {

  private final AbstractTaintInterpreter interpreter = new AbstractTaintInterpreter();

  @Test
  void initialStateHasEmptyStack() {
    AbstractState state = new AbstractState();
    assertEquals(0, state.stackSize());
    assertEquals(TaintState.UNKNOWN, state.peekStack());
  }

  @Test
  void pushAndPopStack() {
    AbstractState state = new AbstractState();
    state.pushStack(TaintState.TAINTED);
    assertEquals(1, state.stackSize());
    assertEquals(TaintState.TAINTED, state.peekStack());
    assertEquals(TaintState.TAINTED, state.popStack());
    assertEquals(0, state.stackSize());
  }

  @Test
  void popStackOnEmptyReturnsUnknown() {
    AbstractState state = new AbstractState();
    assertEquals(TaintState.UNKNOWN, state.popStack());
  }

  @Test
  void setAndGetLocal() {
    AbstractState state = new AbstractState();
    state.setLocal(0, TaintState.TAINTED);
    assertEquals(TaintState.TAINTED, state.getLocal(0));
    assertEquals(TaintState.NOT_TAINTED, state.getLocal(1));
  }

  @Test
  void setLocalWithConstants() {
    AbstractState state = new AbstractState();
    state.setLocal(0, TaintState.NOT_TAINTED, Set.of("const1"));
    assertEquals(Set.of("const1"), state.getLocalConstants(0));
  }

  @Test
  void pushStackWithConstants() {
    AbstractState state = new AbstractState();
    state.pushStack(TaintState.TAINTED, Set.of("value1"));
    assertEquals(Set.of("value1"), state.peekStackConstants());
  }

  @Test
  void peekStackConstantsAtDepth() {
    AbstractState state = new AbstractState();
    state.pushStack(TaintState.NOT_TAINTED, Set.of("first"));
    state.pushStack(TaintState.TAINTED, Set.of("second"));
    assertEquals(Set.of("first"), state.peekStackConstantsAt(1));
    assertEquals(Set.of("second"), state.peekStackConstantsAt(0));
  }

  @Test
  void popStackConstantsReturnsCorrectSet() {
    AbstractState state = new AbstractState();
    state.pushStack(TaintState.TAINTED, Set.of("a", "b"));
    assertEquals(Set.of("a", "b"), state.popStackConstants());
  }

  @Test
  void popStackConstantsOnEmptyReturnsEmpty() {
    AbstractState state = new AbstractState();
    assertTrue(state.popStackConstants().isEmpty());
  }

  @Test
  void copyConstructorCopiesEverything() {
    AbstractState original = new AbstractState();
    original.pushStack(TaintState.TAINTED, Set.of("x"));
    original.setLocal(1, TaintState.NOT_TAINTED);

    AbstractState copy = new AbstractState(original);
    assertEquals(original.stackSize(), copy.stackSize());
    assertEquals(original.peekStack(), copy.peekStack());
    assertEquals(original.getLocal(1), copy.getLocal(1));
  }

  @Test
  void mergeTwoIdenticalStates() {
    AbstractState s1 = new AbstractState();
    s1.pushStack(TaintState.TAINTED);
    s1.setLocal(0, TaintState.NOT_TAINTED);

    AbstractState s2 = new AbstractState(s1);
    AbstractState merged = AbstractState.merge(s1, s2);

    assertEquals(TaintState.TAINTED, merged.peekStack());
    assertEquals(TaintState.NOT_TAINTED, merged.getLocal(0));
  }

  @Test
  void mergeTaintedAndNotTaintedResultIsTainted() {
    AbstractState s1 = new AbstractState();
    s1.pushStack(TaintState.TAINTED);

    AbstractState s2 = new AbstractState();
    s2.pushStack(TaintState.NOT_TAINTED);

    AbstractState merged = AbstractState.merge(s1, s2);
    assertEquals(TaintState.TAINTED, merged.peekStack());
  }

  @Test
  void mergeWithDifferentStackSizes() {
    AbstractState s1 = new AbstractState();
    s1.pushStack(TaintState.TAINTED);
    s1.pushStack(TaintState.NOT_TAINTED);

    AbstractState s2 = new AbstractState();
    s2.pushStack(TaintState.NOT_TAINTED);

    AbstractState merged = AbstractState.merge(s1, s2);
    assertEquals(1, merged.stackSize());
    assertEquals(TaintState.TAINTED, merged.peekStack());
  }

  @Test
  void interpretLdcStringPushesNotTaintedWithConstant() {
    MethodNode method = new MethodNode();
    method.instructions.add(new LdcInsnNode("hello"));
    AbstractState state = interpreter.interpretInstruction(
        method.instructions.getFirst(), new AbstractState());
    assertEquals(TaintState.NOT_TAINTED, state.peekStack());
    assertEquals(Set.of("hello"), state.peekStackConstants());
  }

  @Test
  void interpretLdcIntegerPushesNotTainted() {
    MethodNode method = new MethodNode();
    method.instructions.add(new LdcInsnNode(42));
    AbstractState state = interpreter.interpretInstruction(
        method.instructions.getFirst(), new AbstractState());
    assertEquals(TaintState.NOT_TAINTED, state.peekStack());
  }

  @Test
  void interpretIloadLoadsFromLocal() {
    MethodNode method = new MethodNode();
    method.instructions.add(new VarInsnNode(Opcodes.ILOAD, 0));
    AbstractState before = new AbstractState();
    before.setLocal(0, TaintState.TAINTED, Set.of("fromLocal"));

    AbstractState after = interpreter.interpretInstruction(
        method.instructions.getFirst(), before);
    assertEquals(TaintState.TAINTED, after.peekStack());
    assertEquals(Set.of("fromLocal"), after.peekStackConstants());
  }

  @Test
  void interpretIstoreStoresToLocal() {
    MethodNode method = new MethodNode();
    method.instructions.add(new VarInsnNode(Opcodes.ISTORE, 0));
    AbstractState before = new AbstractState();
    before.pushStack(TaintState.TAINTED, Set.of("stackVal"));

    AbstractState after = interpreter.interpretInstruction(
        method.instructions.getFirst(), before);
    assertEquals(TaintState.TAINTED, after.getLocal(0));
    assertEquals(Set.of("stackVal"), after.getLocalConstants(0));
    assertEquals(0, after.stackSize());
  }

  @Test
  void interpretIconstPushesNotTainted() {
    MethodNode method = new MethodNode();
    method.instructions.add(new InsnNode(Opcodes.ICONST_0));
    AbstractState state = interpreter.interpretInstruction(
        method.instructions.getFirst(), new AbstractState());
    assertEquals(TaintState.NOT_TAINTED, state.peekStack());
  }

  @Test
  void interpretAconstNullPushesNotTainted() {
    MethodNode method = new MethodNode();
    method.instructions.add(new InsnNode(Opcodes.ACONST_NULL));
    AbstractState state = interpreter.interpretInstruction(
        method.instructions.getFirst(), new AbstractState());
    assertEquals(TaintState.NOT_TAINTED, state.peekStack());
  }

  @Test
  void interpretIaddPopsTwoAndPushesNotTainted() {
    MethodNode method = new MethodNode();
    method.instructions.add(new InsnNode(Opcodes.IADD));
    AbstractState before = new AbstractState();
    before.pushStack(TaintState.TAINTED, Set.of("a"));
    before.pushStack(TaintState.NOT_TAINTED, Set.of("b"));

    AbstractState after = interpreter.interpretInstruction(
        method.instructions.getFirst(), before);
    assertEquals(1, after.stackSize());
    assertEquals(TaintState.NOT_TAINTED, after.peekStack());
  }

  @Test
  void interpretReturnPopsOne() {
    MethodNode method = new MethodNode();
    method.instructions.add(new InsnNode(Opcodes.IRETURN));
    AbstractState before = new AbstractState();
    before.pushStack(TaintState.TAINTED);

    AbstractState after = interpreter.interpretInstruction(
        method.instructions.getFirst(), before);
    assertEquals(0, after.stackSize());
  }

  @Test
  void interpretReturnVoidDoesNotPop() {
    MethodNode method = new MethodNode();
    method.instructions.add(new InsnNode(Opcodes.RETURN));
    AbstractState before = new AbstractState();
    before.pushStack(TaintState.TAINTED);

    AbstractState after = interpreter.interpretInstruction(
        method.instructions.getFirst(), before);
    assertEquals(1, after.stackSize());
  }

  @Test
  void interpretPopRemovesOne() {
    MethodNode method = new MethodNode();
    method.instructions.add(new InsnNode(Opcodes.POP));
    AbstractState before = new AbstractState();
    before.pushStack(TaintState.TAINTED);
    before.pushStack(TaintState.NOT_TAINTED);

    AbstractState after = interpreter.interpretInstruction(
        method.instructions.getFirst(), before);
    assertEquals(1, after.stackSize());
  }

  @Test
  void interpretDupDuplicatesTop() {
    MethodNode method = new MethodNode();
    method.instructions.add(new InsnNode(Opcodes.DUP));
    AbstractState before = new AbstractState();
    before.pushStack(TaintState.TAINTED, Set.of("x"));

    AbstractState after = interpreter.interpretInstruction(
        method.instructions.getFirst(), before);
    assertEquals(2, after.stackSize());
    assertEquals(TaintState.TAINTED, after.popStack());
    assertEquals(TaintState.TAINTED, after.popStack());
  }

  @Test
  void interpretSwap() {
    MethodNode method = new MethodNode();
    method.instructions.add(new InsnNode(Opcodes.SWAP));
    AbstractState before = new AbstractState();
    before.pushStack(TaintState.TAINTED, Set.of("a"));
    before.pushStack(TaintState.NOT_TAINTED, Set.of("b"));

    AbstractState after = interpreter.interpretInstruction(
        method.instructions.getFirst(), before);
    assertEquals(TaintState.TAINTED, after.popStack());
    assertEquals(TaintState.NOT_TAINTED, after.popStack());
  }

  @Test
  void interpretGetfieldPopsObjectAndPushesUnknown() {
    MethodNode method = new MethodNode();
    method.instructions.add(new FieldInsnNode(
        Opcodes.GETFIELD, "Foo", "bar", "I"));
    AbstractState before = new AbstractState();
    before.pushStack(TaintState.TAINTED, Set.of("obj"));

    AbstractState after = interpreter.interpretInstruction(
        method.instructions.getFirst(), before);
    assertEquals(TaintState.UNKNOWN, after.peekStack());
    assertEquals(1, after.stackSize());
  }

  @Test
  void interpretGetstaticPushesUnknown() {
    MethodNode method = new MethodNode();
    method.instructions.add(new FieldInsnNode(
        Opcodes.GETSTATIC, "Foo", "BAR", "I"));
    AbstractState state = interpreter.interpretInstruction(
        method.instructions.getFirst(), new AbstractState());
    assertEquals(TaintState.UNKNOWN, state.peekStack());
  }

  @Test
  void interpretNewPushesNotTainted() {
    MethodNode method = new MethodNode();
    method.instructions.add(new TypeInsnNode(Opcodes.NEW, "Foo"));
    AbstractState state = interpreter.interpretInstruction(
        method.instructions.getFirst(), new AbstractState());
    assertEquals(TaintState.NOT_TAINTED, state.peekStack());
  }

  @Test
  void interpretIntInsnPushesNotTainted() {
    MethodNode method = new MethodNode();
    method.instructions.add(new IntInsnNode(Opcodes.BIPUSH, 10));
    AbstractState state = interpreter.interpretInstruction(
        method.instructions.getFirst(), new AbstractState());
    assertEquals(TaintState.NOT_TAINTED, state.peekStack());
  }

  @Test
  void interpretMethodCallPopsArgsAndPushesUnknown() {
    MethodNode method = new MethodNode();
    method.instructions.add(new MethodInsnNode(
        Opcodes.INVOKEVIRTUAL, "Foo", "bar", "(Ljava/lang/String;)Ljava/lang/String;", false));
    AbstractState before = new AbstractState();
    before.pushStack(TaintState.NOT_TAINTED, Set.of("objref"));
    before.pushStack(TaintState.TAINTED, Set.of("arg"));

    AbstractState after = interpreter.interpretInstruction(
        method.instructions.getFirst(), before);
    assertEquals(1, after.stackSize());
    assertEquals(TaintState.UNKNOWN, after.peekStack());
  }

  @Test
  void interpretStaticMethodCallNoObjectRef() {
    MethodNode method = new MethodNode();
    method.instructions.add(new MethodInsnNode(
        Opcodes.INVOKESTATIC, "Foo", "staticBar", "()V", false));
    AbstractState before = new AbstractState();
    before.pushStack(TaintState.TAINTED);

    AbstractState after = interpreter.interpretInstruction(
        method.instructions.getFirst(), before);
    assertEquals(1, after.stackSize());
  }

  @Test
  void interpretArrayLoad() {
    MethodNode method = new MethodNode();
    method.instructions.add(new InsnNode(Opcodes.IALOAD));
    AbstractState before = new AbstractState();
    before.pushStack(TaintState.NOT_TAINTED, Set.of("arr"));
    before.pushStack(TaintState.TAINTED, Set.of("index"));

    AbstractState after = interpreter.interpretInstruction(
        method.instructions.getFirst(), before);
    assertEquals(1, after.stackSize());
    assertEquals(TaintState.NOT_TAINTED, after.peekStack());
  }

  @Test
  void interpretArrayStore() {
    MethodNode method = new MethodNode();
    method.instructions.add(new InsnNode(Opcodes.IASTORE));
    AbstractState before = new AbstractState();
    before.pushStack(TaintState.NOT_TAINTED, Set.of("arr"));
    before.pushStack(TaintState.TAINTED, Set.of("index"));
    before.pushStack(TaintState.NOT_TAINTED, Set.of("val"));

    AbstractState after = interpreter.interpretInstruction(
        method.instructions.getFirst(), before);
    assertEquals(0, after.stackSize());
  }

  @Test
  void analyzeSingleInstruction() {
    MethodNode method = new MethodNode();
    method.instructions.add(new InsnNode(Opcodes.ICONST_0));
    method.instructions.add(new InsnNode(Opcodes.IRETURN));

    AbstractState initialState = new AbstractState();
    var states = interpreter.analyze(method, initialState);
    assertTrue(states.size() >= 2);
  }

  @Test
  void analyzeWithJumpInstruction() {
    LabelNode target = new LabelNode();
    MethodNode method = new MethodNode();
    method.instructions.add(new InsnNode(Opcodes.ICONST_0));
    method.instructions.add(new JumpInsnNode(Opcodes.IFEQ, target));
    method.instructions.add(new InsnNode(Opcodes.ICONST_1));
    method.instructions.add(new InsnNode(Opcodes.IRETURN));
    method.instructions.add(target);
    method.instructions.add(new InsnNode(Opcodes.ICONST_2));
    method.instructions.add(new InsnNode(Opcodes.IRETURN));

    var states = interpreter.analyze(method, new AbstractState());
    assertFalse(states.isEmpty());
  }

  @Test
  void analyzeWithLinearInstructions() {
    MethodNode method = new MethodNode();
    method.instructions.add(new InsnNode(Opcodes.ICONST_0));
    method.instructions.add(new InsnNode(Opcodes.IRETURN));

    var states = interpreter.analyze(method, new AbstractState());
    assertFalse(states.isEmpty());
  }

  @Test
  void equalsAndHashCodeWork() {
    AbstractState s1 = new AbstractState();
    s1.pushStack(TaintState.TAINTED);
    s1.setLocal(0, TaintState.NOT_TAINTED);

    AbstractState s2 = new AbstractState(s1);
    assertEquals(s1, s2);
    assertEquals(s1.hashCode(), s2.hashCode());
  }

  @Test
  void toStringContainsStack() {
    AbstractState state = new AbstractState();
    state.pushStack(TaintState.TAINTED);
    String str = state.toString();
    assertTrue(str.contains("TAINTED"));
  }
}
