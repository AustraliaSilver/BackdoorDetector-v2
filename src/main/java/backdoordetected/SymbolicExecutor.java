package backdoordetected;

import com.microsoft.z3.*;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;
import org.objectweb.asm.util.Textifier;

import java.util.*;
import java.util.logging.Logger;

public class SymbolicExecutor {

    private static final Logger logger = StandaloneLogger.getLogger();

    public List<ExecutionPath> enumeratePaths(MethodNode methodNode) {
        List<ExecutionPath> allPaths = new ArrayList<>();
        if (methodNode.instructions == null || methodNode.instructions.size() == 0) {
            return allPaths;
        }

        try (Context ctx = new Context()) {
            Map<AbstractInsnNode, BasicBlock> cfg = buildCFG(methodNode);
            if (cfg.isEmpty()) return allPaths;

            BasicBlock entry = cfg.get(methodNode.instructions.getFirst());
            if (entry != null) {
                explore(entry, new PathState(ctx), allPaths, new HashSet<>());
            }
        } catch (Exception e) {
            logger.severe("Symbolic execution failed for method " + methodNode.name + ": " + e.getMessage());
            e.printStackTrace();
        }

        return allPaths;
    }

    private void explore(BasicBlock block, PathState state, List<ExecutionPath> allPaths, Set<BasicBlock> visited) {
        if (block == null || !visited.add(block)) return;

        AbstractInsnNode insn = block.start;
        while (insn != null) {
            if (insn.getOpcode() == -1) {
                if (insn == block.end) break;
                insn = insn.getNext();
                continue;
            }

            state.currentPath.addStep(insn);
            executeInstruction(insn, state);

            if (insn == block.end) break;
            insn = insn.getNext();
        }

        if (block.successors.isEmpty()) {
            allPaths.add(new ExecutionPath(state.currentPath));
            return;
        }

        for (BasicBlock successor : block.successors) {
            PathState newState = state.copy();

            BoolExpr cond = createBranchCondition(block.end, successor, newState);
            if (cond != null) {
                newState.solver.add(cond);
            }

            if (newState.solver.check() == Status.SATISFIABLE) {
                explore(successor, newState, allPaths, new HashSet<>(visited));
            }
        }
    }

    private void executeInstruction(AbstractInsnNode insn, PathState state) {
        int opcode = insn.getOpcode();
        Context ctx = state.ctx;

        switch (opcode) {
            case Opcodes.DUP -> {
                if (state.stack.isEmpty()) return;
                Expr<?> top = state.stack.peek();
                state.stack.push(top);
            }
            case Opcodes.DUP_X1 -> {
                if (state.stack.size() < 2) return;
                Expr<?> v1 = state.stack.pop();
                Expr<?> v2 = state.stack.pop();
                state.stack.push(v1); state.stack.push(v2); state.stack.push(v1);
            }
            case Opcodes.DUP_X2 -> {
                if (state.stack.size() < 3) return;
                Expr<?> v1 = state.stack.pop();
                Expr<?> v2 = state.stack.pop();
                Expr<?> v3 = state.stack.pop();
                state.stack.push(v1); state.stack.push(v3); state.stack.push(v2); state.stack.push(v1);
            }
            case Opcodes.DUP2 -> {
                if (state.stack.size() < 2) return;
                Expr<?> v1 = state.stack.pop();
                Expr<?> v2 = state.stack.pop();
                state.stack.push(v2); state.stack.push(v1); state.stack.push(v2); state.stack.push(v1);
            }
            case Opcodes.POP -> {
                if (!state.stack.isEmpty()) state.stack.pop();
            }
            case Opcodes.POP2 -> {
                if (state.stack.size() >= 2) { state.stack.pop(); state.stack.pop(); }
                else if (!state.stack.isEmpty()) state.stack.pop();
            }
            case Opcodes.SWAP -> {
                if (state.stack.size() < 2) return;
                Expr<?> a = state.stack.pop();
                Expr<?> b = state.stack.pop();
                state.stack.push(a); state.stack.push(b);
            }

            case Opcodes.ICONST_M1, Opcodes.ICONST_0, Opcodes.ICONST_1, Opcodes.ICONST_2,
                 Opcodes.ICONST_3, Opcodes.ICONST_4, Opcodes.ICONST_5 -> {
                int val = opcode - Opcodes.ICONST_0;
                state.stack.push(ctx.mkInt(val));
            }
            case Opcodes.BIPUSH, Opcodes.SIPUSH -> {
                int val = ((IntInsnNode) insn).operand;
                state.stack.push(ctx.mkInt(val));
            }
            case Opcodes.LDC -> {
                LdcInsnNode ldc = (LdcInsnNode) insn;
                Object cst = ldc.cst;
                if (cst instanceof Integer i) state.stack.push(ctx.mkInt(i));
                else if (cst instanceof String s) state.stack.push(ctx.mkString(s));
                else if (cst instanceof Float f) state.stack.push(ctx.mkReal(f.toString()));
                else if (cst instanceof Long l) state.stack.push(ctx.mkInt(l));
                else if (cst instanceof Double d) state.stack.push(ctx.mkReal(d.toString()));
            }

            case Opcodes.ILOAD -> {
                VarInsnNode var = (VarInsnNode) insn;
                Expr<?> val = state.locals.getOrDefault(var.var, ctx.mkIntConst("v" + var.var));
                state.stack.push(val);
            }
            case Opcodes.ISTORE -> {
                if (state.stack.isEmpty()) return;
                VarInsnNode var = (VarInsnNode) insn;
                state.locals.put(var.var, state.stack.pop());
            }
            case Opcodes.ALOAD -> {
                VarInsnNode var = (VarInsnNode) insn;
                Expr<?> val = state.locals.getOrDefault(var.var, ctx.mkConst("ref" + var.var, ctx.getStringSort()));
                state.stack.push(val);
            }
            case Opcodes.ASTORE -> {
                if (state.stack.isEmpty()) return;
                VarInsnNode var = (VarInsnNode) insn;
                state.locals.put(var.var, state.stack.pop());
            }

            case Opcodes.IADD, Opcodes.ISUB, Opcodes.IMUL, Opcodes.IDIV -> {
                if (state.stack.size() < 2) return;
                Expr<?> e2 = state.stack.pop();
                Expr<?> e1 = state.stack.pop();
                if (!(e1 instanceof ArithExpr a1) || !(e2 instanceof ArithExpr a2)) return;

                Expr<?> result = switch (opcode) {
                    case Opcodes.IADD -> ctx.mkAdd(a1, a2);
                    case Opcodes.ISUB -> ctx.mkSub(a1, a2);
                    case Opcodes.IMUL -> ctx.mkMul(a1, a2);
                    case Opcodes.IDIV -> ctx.mkDiv(a1, a2);
                    default -> ctx.mkInt(0);
                };
                state.stack.push(result);
            }
            case Opcodes.IINC -> {
                IincInsnNode iinc = (IincInsnNode) insn;
                Expr<?> cur = state.locals.get(iinc.var);
                if (cur instanceof ArithExpr a) {
                    state.locals.put(iinc.var, ctx.mkAdd(a, ctx.mkInt(iinc.incr)));
                }
            }

            case Opcodes.GETSTATIC, Opcodes.GETFIELD -> {
                state.stack.push(ctx.mkConst("field_ref", ctx.getStringSort()));
            }
            case Opcodes.INVOKEVIRTUAL, Opcodes.INVOKESTATIC, Opcodes.INVOKEINTERFACE, Opcodes.INVOKESPECIAL -> {
                MethodInsnNode min = (MethodInsnNode) insn;
                String retType = min.desc.substring(min.desc.indexOf(')') + 1);
                if (!retType.equals("V")) {
                    state.stack.push(switch (retType) {
                        case "I", "Z", "B", "C", "S" -> ctx.mkIntConst("invoke_int");
                        case "J" -> ctx.mkIntConst("invoke_long");
                        case "F" -> ctx.mkReal("0.0");
                        case "D" -> ctx.mkReal("0.0");
                        case "Ljava/lang/String;" -> ctx.mkString("invoke_str");
                        default -> ctx.mkConst("invoke_ref", ctx.getStringSort());
                    });
                }
                int argCount = countMethodArgs(min.desc);
                for (int i = 0; i < argCount && !state.stack.isEmpty(); i++) {
                    state.stack.pop();
                }
                if (opcode != Opcodes.INVOKESTATIC) {
                    if (!state.stack.isEmpty()) state.stack.pop();
                }
                state.currentPath.addNote("Call: " + min.owner + "." + min.name + min.desc);
            }

            case Opcodes.RETURN, Opcodes.IRETURN, Opcodes.ARETURN -> {
            }

            default -> {
                logger.fine("Unhandled opcode: " + Textifier.OPCODES[opcode]);
            }
        }
    }

    private int countMethodArgs(String desc) {
        int count = 0;
        int i = 1;
        while (i < desc.length() && desc.charAt(i) != ')') {
            char c = desc.charAt(i);
            if (c == 'L') {
                i = desc.indexOf(';', i) + 1;
            } else if (c == '[') {
                while (i < desc.length() && desc.charAt(i) == '[') i++;
                if (i < desc.length() && desc.charAt(i) == 'L') {
                    i = desc.indexOf(';', i) + 1;
                } else {
                    i++;
                }
            } else {
                i++;
            }
            count++;
        }
        return count;
    }

    private BoolExpr createBranchCondition(AbstractInsnNode jumpInsn, BasicBlock target, PathState state) {
        if (!(jumpInsn instanceof JumpInsnNode jinsn)) return null;

        Context ctx = state.ctx;
        int opcode = jinsn.getOpcode();

        boolean taken = isTargetOfJump(jinsn, target);

        Stack<Expr<?>> tempStack = new Stack<>();
        tempStack.addAll(state.stack);

        if ((opcode >= Opcodes.IF_ICMPEQ && opcode <= Opcodes.IF_ICMPLE) ||
            opcode == Opcodes.IF_ACMPEQ || opcode == Opcodes.IF_ACMPNE) {

            if (tempStack.size() < 2) return null;
            Expr<?> v2 = tempStack.pop();
            Expr<?> v1 = tempStack.pop();

            if (v1 instanceof ArithExpr a1 && v2 instanceof ArithExpr a2) {
                BoolExpr cond = createIntComparison(ctx, opcode, a1, a2);
                return taken ? cond : ctx.mkNot(cond);
            }
            if (opcode == Opcodes.IF_ACMPEQ || opcode == Opcodes.IF_ACMPNE) {
                BoolExpr eq = ctx.mkEq(v1, v2);
                return (opcode == Opcodes.IF_ACMPEQ) == taken ? eq : ctx.mkNot(eq);
            }
            return ctx.mkFalse();
        }
if ((opcode >= Opcodes.IFEQ && opcode <= Opcodes.IFLE) ||
    opcode == Opcodes.IFNULL || opcode == Opcodes.IFNONNULL) {

    if (tempStack.isEmpty()) return null;
    Expr<?> v = tempStack.pop();

    if (opcode == Opcodes.IFNULL || opcode == Opcodes.IFNONNULL) {
        if (!v.getSort().equals(ctx.getStringSort())) {
            return ctx.mkFalse();
        }
        Expr<?> nullSym = ctx.mkString("SYMBOLIC_NULL");
        BoolExpr eq = ctx.mkEq(v, nullSym);
        return (opcode == Opcodes.IFNULL) == taken ? eq : ctx.mkNot(eq);
    }

    if (v instanceof ArithExpr a) {
        BoolExpr cond = createZeroComparison(ctx, opcode, a, ctx.mkInt(0));
        return taken ? cond : ctx.mkNot(cond);
    }
    return ctx.mkFalse();
}
        return null;
    }

    private boolean isTargetOfJump(JumpInsnNode jump, BasicBlock target) {
        if (jump.label == target.start) return true;
        if (jump.getNext() == target.start && jump.getOpcode() != Opcodes.GOTO) return true;
        return false;
    }

    private BoolExpr createIntComparison(Context ctx, int opcode, ArithExpr v1, ArithExpr v2) {
        return switch (opcode) {
            case Opcodes.IF_ICMPEQ -> ctx.mkEq(v1, v2);
            case Opcodes.IF_ICMPNE -> ctx.mkNot(ctx.mkEq(v1, v2));
            case Opcodes.IF_ICMPLT -> ctx.mkLt(v1, v2);
            case Opcodes.IF_ICMPGE -> ctx.mkGe(v1, v2);
            case Opcodes.IF_ICMPGT -> ctx.mkGt(v1, v2);
            case Opcodes.IF_ICMPLE -> ctx.mkLe(v1, v2);
            default -> ctx.mkTrue();
        };
    }

    private BoolExpr createZeroComparison(Context ctx, int opcode, ArithExpr v, ArithExpr zero) {
        return switch (opcode) {
            case Opcodes.IFEQ -> ctx.mkEq(v, zero);
            case Opcodes.IFNE -> ctx.mkNot(ctx.mkEq(v, zero));
            case Opcodes.IFLT -> ctx.mkLt(v, zero);
            case Opcodes.IFGE -> ctx.mkGe(v, zero);
            case Opcodes.IFGT -> ctx.mkGt(v, zero);
            case Opcodes.IFLE -> ctx.mkLe(v, zero);
            default -> ctx.mkTrue();
        };
    }

    private Map<AbstractInsnNode, BasicBlock> buildCFG(MethodNode methodNode) {
        Map<AbstractInsnNode, BasicBlock> blocks = new LinkedHashMap<>();
        InsnList instructions = methodNode.instructions;
        if (instructions.size() == 0) return blocks;

        Set<LabelNode> leaders = new HashSet<>();
        AbstractInsnNode first = instructions.getFirst();
        LabelNode firstLabel = extractLabel(first);
        if (firstLabel != null) leaders.add(firstLabel);

        for (AbstractInsnNode insn : instructions) {
            if (insn instanceof JumpInsnNode j) {
                leaders.add(j.label);
                if (insn.getNext() != null) {
                    LabelNode next = extractLabel(insn.getNext());
                    if (next != null) leaders.add(next);
                }
            } else if (insn instanceof TableSwitchInsnNode ts) {
                leaders.add(ts.dflt);
                ts.labels.forEach(leaders::add);
                if (insn.getNext() != null) {
                    LabelNode next = extractLabel(insn.getNext());
                    if (next != null) leaders.add(next);
                }
            } else if (insn instanceof LookupSwitchInsnNode ls) {
                leaders.add(ls.dflt);
                ls.labels.forEach(leaders::add);
                if (insn.getNext() != null) {
                    LabelNode next = extractLabel(insn.getNext());
                    if (next != null) leaders.add(next);
                }
            }
        }

        BasicBlock current = null;
        for (AbstractInsnNode insn : instructions) {
            LabelNode label = extractLabel(insn);
            if (leaders.contains(label)) {
                current = new BasicBlock(insn);
                blocks.put(insn, current);
            }
            if (current != null) current.end = insn;
        }

        for (BasicBlock b : blocks.values()) {
            AbstractInsnNode last = b.end;
            if (last == null) continue;

            if (last instanceof JumpInsnNode j) {
                BasicBlock target = blocks.get(j.label);
                if (target != null) b.successors.add(target);
                if (j.getOpcode() != Opcodes.GOTO && last.getNext() != null) {
                    BasicBlock fall = blocks.get(last.getNext());
                    if (fall != null) b.successors.add(fall);
                }
            } else if (last instanceof TableSwitchInsnNode ts) {
                BasicBlock dflt = blocks.get(ts.dflt);
                if (dflt != null) b.successors.add(dflt);
                for (LabelNode lbl : ts.labels) {
                    BasicBlock t = blocks.get(lbl);
                    if (t != null) b.successors.add(t);
                }
            } else if (last instanceof LookupSwitchInsnNode ls) {
                BasicBlock dflt = blocks.get(ls.dflt);
                if (dflt != null) b.successors.add(dflt);
                for (LabelNode lbl : ls.labels) {
                    BasicBlock t = blocks.get(lbl);
                    if (t != null) b.successors.add(t);
                }
            } else if (last.getOpcode() != Opcodes.ATHROW &&
                       (last.getOpcode() < Opcodes.IRETURN || last.getOpcode() > Opcodes.RETURN)) {
                if (last.getNext() != null) {
                    BasicBlock next = blocks.get(last.getNext());
                    if (next != null) b.successors.add(next);
                }
            }
        }
        return blocks;
    }

    private LabelNode extractLabel(AbstractInsnNode node) {
        return node instanceof LabelNode l ? l : null;
    }

    private static class BasicBlock {
        final AbstractInsnNode start;
        AbstractInsnNode end;
        final List<BasicBlock> successors = new ArrayList<>();
        BasicBlock(AbstractInsnNode start) { this.start = start; this.end = start; }
    }

    private static class PathState {
        final Context ctx;
        final Solver solver;
        final Stack<Expr<?>> stack = new Stack<>();
        final Map<Integer, Expr<?>> locals = new HashMap<>();
        final ExecutionPath currentPath = new ExecutionPath();

        PathState(Context ctx) {
            this.ctx = ctx;
            this.solver = ctx.mkSolver();
        }

        PathState(PathState other) {
            this.ctx = other.ctx;
            this.solver = ctx.mkSolver();
            this.solver.add(other.solver.getAssertions());
            this.stack.addAll(other.stack);
            this.locals.putAll(other.locals);
            this.currentPath.steps.addAll(other.currentPath.steps);
            this.currentPath.notes.addAll(other.currentPath.notes);
        }

        public PathState copy() { return new PathState(this); }
    }

    public static class ExecutionPath {
        final List<String> steps = new ArrayList<>();
        final List<String> notes = new ArrayList<>();

        ExecutionPath() {}
        ExecutionPath(ExecutionPath o) { steps.addAll(o.steps); notes.addAll(o.notes); }

        void addStep(AbstractInsnNode insn) {
            steps.add("OP:" + insn.getOpcode());
        }
        void addNote(String note) { notes.add(note); }

        @Override
        public String toString() {
            return "Path: " + String.join(" → ", steps) + "\nNotes: " + String.join(", ", notes);
        }
    }
}