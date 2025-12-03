package backdoordetected.detection;

import java.util.*;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;

public class AbstractTaintInterpreter {

  public enum TaintState {
    TAINTED,
    NOT_TAINTED,
    UNKNOWN
  }

  public static class AbstractState {
    private final List<TaintState> stack;
    private final Map<Integer, TaintState> locals;
    private final List<Set<String>> stackConstants;
    private final Map<Integer, Set<String>> localConstants;

    public AbstractState() {
      this.stack = new ArrayList<>();
      this.locals = new HashMap<>();
      this.stackConstants = new ArrayList<>();
      this.localConstants = new HashMap<>();
    }

    public AbstractState(AbstractState other) {
      this.stack = new ArrayList<>(other.stack);
      this.locals = new HashMap<>(other.locals);
      this.stackConstants = new ArrayList<>(other.stackConstants);
      this.localConstants = new HashMap<>(other.localConstants);
    }

    public void pushStack(TaintState state) {
      pushStack(state, Collections.emptySet());
    }

    public void pushStack(TaintState state, Set<String> constants) {
      stack.add(state);
      stackConstants.add(constants != null ? new HashSet<>(constants) : Collections.emptySet());
    }

    public TaintState popStack() {
      if (stack.isEmpty()) {
        return TaintState.UNKNOWN;
      }
      if (!stackConstants.isEmpty()) {
        stackConstants.remove(stackConstants.size() - 1);
      }
      return stack.remove(stack.size() - 1);
    }

    public Set<String> popStackConstants() {
      if (stackConstants.isEmpty()) {
        return Collections.emptySet();
      }
      return stackConstants.remove(stackConstants.size() - 1);
    }

    public TaintState peekStack() {
      if (stack.isEmpty()) {
        return TaintState.UNKNOWN;
      }
      return stack.get(stack.size() - 1);
    }

    public Set<String> peekStackConstants() {
      if (stackConstants.isEmpty()) {
        return Collections.emptySet();
      }
      return new HashSet<>(stackConstants.get(stackConstants.size() - 1));
    }

    public Set<String> peekStackConstantsAt(int depth) {
      int index = stackConstants.size() - 1 - depth;
      if (index < 0 || index >= stackConstants.size()) {
        return Collections.emptySet();
      }
      return new HashSet<>(stackConstants.get(index));
    }

    public void setLocal(int index, TaintState state) {
      setLocal(index, state, Collections.emptySet());
    }

    public void setLocal(int index, TaintState state, Set<String> constants) {
      locals.put(index, state);
      localConstants.put(
          index, constants != null ? new HashSet<>(constants) : Collections.emptySet());
    }

    public TaintState getLocal(int index) {
      return locals.getOrDefault(index, TaintState.NOT_TAINTED);
    }

    public Set<String> getLocalConstants(int index) {
      return new HashSet<>(localConstants.getOrDefault(index, Collections.emptySet()));
    }

    public int stackSize() {
      return stack.size();
    }

    public static AbstractState merge(AbstractState s1, AbstractState s2) {
      AbstractState result = new AbstractState();

      Set<Integer> allLocals = new HashSet<>();
      allLocals.addAll(s1.locals.keySet());
      allLocals.addAll(s2.locals.keySet());

      for (int local : allLocals) {
        TaintState t1 = s1.getLocal(local);
        TaintState t2 = s2.getLocal(local);
        Set<String> c1 = s1.getLocalConstants(local);
        Set<String> c2 = s2.getLocalConstants(local);
        result.setLocal(local, mergeTaint(t1, t2), mergeConstants(c1, c2));
      }

      int minSize = Math.min(s1.stackSize(), s2.stackSize());
      for (int i = 0; i < minSize; i++) {
        TaintState t1 = s1.stack.get(i);
        TaintState t2 = s2.stack.get(i);
        Set<String> c1 = s1.stackConstants.get(i);
        Set<String> c2 = s2.stackConstants.get(i);
        result.pushStack(mergeTaint(t1, t2), mergeConstants(c1, c2));
      }

      return result;
    }

    private static TaintState mergeTaint(TaintState t1, TaintState t2) {
      if (t1 == t2)
        return t1;
      if (t1 == TaintState.TAINTED || t2 == TaintState.TAINTED) {
        return TaintState.TAINTED;
      }
      return TaintState.UNKNOWN;
    }

    private static Set<String> mergeConstants(Set<String> c1, Set<String> c2) {
      if (c1.equals(c2))
        return new HashSet<>(c1);
      Set<String> result = new HashSet<>(c1);
      result.addAll(c2);
      return result;
    }

    @Override
    public boolean equals(Object obj) {
      if (!(obj instanceof AbstractState))
        return false;
      AbstractState other = (AbstractState) obj;
      return stack.equals(other.stack)
          && locals.equals(other.locals)
          && stackConstants.equals(other.stackConstants)
          && localConstants.equals(other.localConstants);
    }

    @Override
    public int hashCode() {
      return Objects.hash(stack, locals, stackConstants, localConstants);
    }

    @Override
    public String toString() {
      return "State{stack=" + stack + ", locals=" + locals + "}";
    }
  }

  public AbstractState interpretInstruction(AbstractInsnNode insn, AbstractState state) {
    AbstractState newState = new AbstractState(state);

    int opcode = insn.getOpcode();

    if (insn instanceof VarInsnNode) {
      VarInsnNode varInsn = (VarInsnNode) insn;

      if (opcode >= Opcodes.ILOAD && opcode <= Opcodes.ALOAD) {
        TaintState localTaint = newState.getLocal(varInsn.var);
        Set<String> localConsts = newState.getLocalConstants(varInsn.var);
        newState.pushStack(localTaint, localConsts);
      } else if (opcode >= Opcodes.ISTORE && opcode <= Opcodes.ASTORE) {
        TaintState stackTaint = newState.popStack();
        Set<String> stackConsts = newState.popStackConstants();
        newState.setLocal(varInsn.var, stackTaint, stackConsts);
      }
    } else if (insn instanceof LdcInsnNode) {
      LdcInsnNode ldc = (LdcInsnNode) insn;
      Set<String> consts = new HashSet<>();
      if (ldc.cst instanceof String) {
        consts.add((String) ldc.cst);
      }
      newState.pushStack(TaintState.NOT_TAINTED, consts);
    } else if (insn instanceof InsnNode) {
      if (opcode >= Opcodes.ICONST_M1 && opcode <= Opcodes.DCONST_1) {
        newState.pushStack(TaintState.NOT_TAINTED, Collections.emptySet());
      } else if (opcode == Opcodes.ACONST_NULL) {
        newState.pushStack(TaintState.NOT_TAINTED, Collections.emptySet());
      } else if (opcode >= Opcodes.IADD && opcode <= Opcodes.LXOR) {
        newState.popStack();
        newState.popStackConstants();
        newState.popStack();
        newState.popStackConstants();
        newState.pushStack(TaintState.NOT_TAINTED, Collections.emptySet());
      } else if (opcode >= Opcodes.IRETURN && opcode <= Opcodes.RETURN) {
        if (opcode != Opcodes.RETURN) {
          newState.popStack();
          newState.popStackConstants();
        }
      } else if (opcode >= Opcodes.IALOAD && opcode <= Opcodes.SALOAD) {
        newState.popStack();
        newState.popStackConstants();
        TaintState arrayTaint = newState.popStack();
        newState.popStackConstants();
        newState.pushStack(arrayTaint, Collections.emptySet());
      } else if (opcode >= Opcodes.IASTORE && opcode <= Opcodes.SASTORE) {
        newState.popStack();
        newState.popStackConstants();
        newState.popStack();
        newState.popStackConstants();
        newState.popStack();
        newState.popStackConstants();
      } else if (opcode == Opcodes.POP) {
        newState.popStack();
        newState.popStackConstants();
      } else if (opcode == Opcodes.POP2) {
        newState.popStack();
        newState.popStackConstants();
        if (newState.stackSize() > 0) {
          newState.popStack();
          newState.popStackConstants();
        }
      } else if (opcode == Opcodes.DUP) {
        TaintState top = newState.peekStack();
        Set<String> topConsts = newState.peekStackConstants();
        newState.pushStack(top, topConsts);
      } else if (opcode == Opcodes.SWAP) {
        TaintState t1 = newState.popStack();
        Set<String> c1 = newState.popStackConstants();
        TaintState t2 = newState.popStack();
        Set<String> c2 = newState.popStackConstants();
        newState.pushStack(t1, c1);
        newState.pushStack(t2, c2);
      }
    } else if (insn instanceof IntInsnNode) {
      newState.pushStack(TaintState.NOT_TAINTED, Collections.emptySet());
    } else if (insn instanceof FieldInsnNode) {
      if (opcode == Opcodes.GETFIELD) {
        newState.popStack();
        newState.popStackConstants();
        newState.pushStack(TaintState.UNKNOWN, Collections.emptySet());
      } else if (opcode == Opcodes.PUTFIELD) {
        newState.popStack();
        newState.popStackConstants();
        newState.popStack();
        newState.popStackConstants();
      } else if (opcode == Opcodes.GETSTATIC) {
        newState.pushStack(TaintState.UNKNOWN, Collections.emptySet());
      } else if (opcode == Opcodes.PUTSTATIC) {
        newState.popStack();
        newState.popStackConstants();
      }
    } else if (insn instanceof MethodInsnNode) {
      MethodInsnNode methodInsn = (MethodInsnNode) insn;
      int argCount = org.objectweb.asm.Type.getArgumentTypes(methodInsn.desc).length;
      for (int i = 0; i < argCount; i++) {
        newState.popStack();
        newState.popStackConstants();
      }
      if (opcode != Opcodes.INVOKESTATIC) {
        newState.popStack();
        newState.popStackConstants();
      }
      org.objectweb.asm.Type returnType = org.objectweb.asm.Type.getReturnType(methodInsn.desc);
      if (returnType.getSort() != org.objectweb.asm.Type.VOID) {
        newState.pushStack(TaintState.UNKNOWN, Collections.emptySet());
      }
    } else if (insn instanceof TypeInsnNode) {
      if (opcode == Opcodes.NEW) {
        newState.pushStack(TaintState.NOT_TAINTED, Collections.emptySet());
      } else if (opcode == Opcodes.CHECKCAST) {
      }
    } else if (insn instanceof IincInsnNode) {
    }

    return newState;
  }

  public Map<AbstractInsnNode, AbstractState> analyze(
      MethodNode method, AbstractState initialState) {

    Map<AbstractInsnNode, AbstractState> states = new HashMap<>();
    Queue<AbstractInsnNode> worklist = new LinkedList<>();

    AbstractInsnNode first = method.instructions.getFirst();
    states.put(first, initialState);
    worklist.add(first);

    while (!worklist.isEmpty()) {
      AbstractInsnNode insn = worklist.poll();
      AbstractState currentState = states.get(insn);

      if (currentState == null)
        continue;

      AbstractState newState = interpretInstruction(insn, currentState);

      AbstractInsnNode next = insn.getNext();
      if (next != null) {
        AbstractState oldState = states.get(next);
        if (oldState == null) {
          states.put(next, newState);
          worklist.add(next);
        } else {
          AbstractState merged = AbstractState.merge(oldState, newState);
          if (!merged.equals(oldState)) {
            states.put(next, merged);
            worklist.add(next);
          }
        }
      }

      if (insn instanceof JumpInsnNode) {
        JumpInsnNode jumpInsn = (JumpInsnNode) insn;
        LabelNode target = jumpInsn.label;

        AbstractInsnNode targetInsn = method.instructions.getFirst();
        while (targetInsn != null) {
          if (targetInsn == target) {
            AbstractState oldState = states.get(targetInsn);
            if (oldState == null) {
              states.put(targetInsn, newState);
              worklist.add(targetInsn);
            } else {
              AbstractState merged = AbstractState.merge(oldState, newState);
              if (!merged.equals(oldState)) {
                states.put(targetInsn, merged);
                worklist.add(targetInsn);
              }
            }
            break;
          }
          targetInsn = targetInsn.getNext();
        }
      }
    }

    return states;
  }
}
