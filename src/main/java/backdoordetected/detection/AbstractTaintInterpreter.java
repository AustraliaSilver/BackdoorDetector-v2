package backdoordetected.detection;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;

import java.util.*;


public class AbstractTaintInterpreter {

    
    public enum TaintState {
        TAINTED, 
        NOT_TAINTED, 
        UNKNOWN 
    }

    
    public static class AbstractState {
        private final List<TaintState> stack; 
        private final Map<Integer, TaintState> locals; 

        public AbstractState() {
            this.stack = new ArrayList<>();
            this.locals = new HashMap<>();
        }

        public AbstractState(AbstractState other) {
            this.stack = new ArrayList<>(other.stack);
            this.locals = new HashMap<>(other.locals);
        }

        public void pushStack(TaintState state) {
            stack.add(state);
        }

        public TaintState popStack() {
            if (stack.isEmpty()) {
                return TaintState.UNKNOWN;
            }
            return stack.remove(stack.size() - 1);
        }

        public TaintState peekStack() {
            if (stack.isEmpty()) {
                return TaintState.UNKNOWN;
            }
            return stack.get(stack.size() - 1);
        }

        public void setLocal(int index, TaintState state) {
            locals.put(index, state);
        }

        public TaintState getLocal(int index) {
            return locals.getOrDefault(index, TaintState.NOT_TAINTED);
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
                result.setLocal(local, mergeTaint(t1, t2));
            }

            
            int minSize = Math.min(s1.stackSize(), s2.stackSize());
            for (int i = 0; i < minSize; i++) {
                TaintState t1 = s1.stack.get(i);
                TaintState t2 = s2.stack.get(i);
                result.stack.add(mergeTaint(t1, t2));
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

        @Override
        public boolean equals(Object obj) {
            if (!(obj instanceof AbstractState))
                return false;
            AbstractState other = (AbstractState) obj;
            return stack.equals(other.stack) && locals.equals(other.locals);
        }

        @Override
        public int hashCode() {
            return Objects.hash(stack, locals);
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
                newState.pushStack(localTaint);
            } else if (opcode >= Opcodes.ISTORE && opcode <= Opcodes.ASTORE) {
                
                TaintState stackTaint = newState.popStack();
                newState.setLocal(varInsn.var, stackTaint);
            }
        }

        
        else if (insn instanceof InsnNode) {
            if (opcode >= Opcodes.ICONST_M1 && opcode <= Opcodes.DCONST_1) {
                
                newState.pushStack(TaintState.NOT_TAINTED);
            } else if (opcode == Opcodes.ACONST_NULL) {
                newState.pushStack(TaintState.NOT_TAINTED);
            }
            
            else if (opcode >= Opcodes.IADD && opcode <= Opcodes.LXOR) {
                
                TaintState t2 = newState.popStack();
                TaintState t1 = newState.popStack();
                
                TaintState result = (t1 == TaintState.TAINTED || t2 == TaintState.TAINTED)
                        ? TaintState.TAINTED
                        : TaintState.NOT_TAINTED;
                newState.pushStack(result);
            }
            
            else if (opcode >= Opcodes.IRETURN && opcode <= Opcodes.RETURN) {
                if (opcode != Opcodes.RETURN) {
                    newState.popStack(); 
                }
            }
            
            else if (opcode >= Opcodes.IALOAD && opcode <= Opcodes.SALOAD) {
                newState.popStack(); 
                TaintState arrayTaint = newState.popStack(); 
                newState.pushStack(arrayTaint); 
            } else if (opcode >= Opcodes.IASTORE && opcode <= Opcodes.SASTORE) {
                TaintState valueTaint = newState.popStack(); 
                newState.popStack(); 
                newState.popStack(); 
                
            }
            
            else if (opcode == Opcodes.POP) {
                newState.popStack();
            } else if (opcode == Opcodes.POP2) {
                newState.popStack();
                newState.popStack();
            } else if (opcode == Opcodes.DUP) {
                TaintState top = newState.peekStack();
                newState.pushStack(top);
            } else if (opcode == Opcodes.SWAP) {
                TaintState t1 = newState.popStack();
                TaintState t2 = newState.popStack();
                newState.pushStack(t1);
                newState.pushStack(t2);
            }
        }

        
        else if (insn instanceof LdcInsnNode) {
            newState.pushStack(TaintState.NOT_TAINTED);
        }

        
        else if (insn instanceof FieldInsnNode) {
            FieldInsnNode fieldInsn = (FieldInsnNode) insn;

            if (opcode == Opcodes.GETFIELD) {
                newState.popStack(); 
                
                newState.pushStack(TaintState.UNKNOWN);
            } else if (opcode == Opcodes.PUTFIELD) {
                newState.popStack(); 
                newState.popStack(); 
            } else if (opcode == Opcodes.GETSTATIC) {
                newState.pushStack(TaintState.UNKNOWN);
            } else if (opcode == Opcodes.PUTSTATIC) {
                newState.popStack(); 
            }
        }

        
        else if (insn instanceof MethodInsnNode) {
            MethodInsnNode methodInsn = (MethodInsnNode) insn;

            
            int argCount = org.objectweb.asm.Type.getArgumentTypes(methodInsn.desc).length;
            for (int i = 0; i < argCount; i++) {
                newState.popStack();
            }

            
            if (opcode != Opcodes.INVOKESTATIC) {
                newState.popStack();
            }

            
            org.objectweb.asm.Type returnType = org.objectweb.asm.Type.getReturnType(methodInsn.desc);
            if (returnType.getSort() != org.objectweb.asm.Type.VOID) {
                
                newState.pushStack(TaintState.UNKNOWN);
            }
        }

        
        else if (insn instanceof TypeInsnNode) {
            if (opcode == Opcodes.NEW) {
                newState.pushStack(TaintState.NOT_TAINTED);
            } else if (opcode == Opcodes.CHECKCAST) {
                
            }
        }

        
        else if (insn instanceof IincInsnNode) {
            
        }

        return newState;
    }

    
    public Map<AbstractInsnNode, AbstractState> analyze(
            MethodNode method,
            AbstractState initialState) {

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
