package backdoordetected.detection;

import backdoordetected.utils.StandaloneLogger;
import backdoordetected.analyzers.CFGAnalyzer;
import com.microsoft.z3.*;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;
import backdoordetected.analyzers.CFGAnalyzer.BasicBlock;
import java.util.*;
import java.util.logging.Logger;

public class PathSensitiveCFG {
    private static final Logger logger = StandaloneLogger.getLogger();

    private static final int MAX_PATHS = 100;
    private static final int MAX_PATH_LENGTH = 50;
    private static final int Z3_TIMEOUT_MS = 5000;

    private final Context z3Context;
    private final Set<String> dangerousSinks;

    public PathSensitiveCFG() {

        HashMap<String, String> cfg = new HashMap<>();
        cfg.put("model", "true");
        cfg.put("timeout", String.valueOf(Z3_TIMEOUT_MS));
        this.z3Context = new Context(cfg);

        this.dangerousSinks = new HashSet<>();
        initializeDangerousSinks();
    }

    private void initializeDangerousSinks() {
        dangerousSinks.add("java/lang/Runtime.exec");
        dangerousSinks.add("java/lang/ProcessBuilder.start");
        dangerousSinks.add("java/lang/Class.forName");
        dangerousSinks.add("java/lang/reflect/Method.invoke");
        dangerousSinks.add("org/bukkit/Bukkit.dispatchCommand");
        dangerousSinks.add("org/bukkit/Server.dispatchCommand");
        dangerousSinks.add("javax/naming/Context.lookup");
        dangerousSinks.add("java/lang/ClassLoader.defineClass");
    }

    public void analyzePaths(MethodNode methodNode, String className, Set<String> findings) {
        try {

            CFGAnalyzer cfgAnalyzer = new CFGAnalyzer();
            Map<AbstractInsnNode, BasicBlock> blockMap = buildBasicBlocks(methodNode, cfgAnalyzer);

            if (blockMap.isEmpty()) {
                return;
            }

            BasicBlock entryBlock = blockMap.get(methodNode.instructions.getFirst());
            if (entryBlock == null) {
                return;
            }

            Queue<CFGPath> workList = new LinkedList<>();
            workList.add(new CFGPath(entryBlock, z3Context.mkTrue()));

            int pathsExplored = 0;
            Set<BasicBlock> visitedBlocks = new HashSet<>();

            while (!workList.isEmpty() && pathsExplored < MAX_PATHS) {
                CFGPath current = workList.poll();
                pathsExplored++;

                if (current.getLength() > MAX_PATH_LENGTH) {
                    continue;
                }

                BasicBlock currentBlock = current.getCurrentBlock();
                visitedBlocks.add(currentBlock);

                if (containsDangerousSink(currentBlock)) {

                    if (isPathSatisfiable(current)) {
                        reportVulnerability(current, className, methodNode.name, findings);
                    }
                }

                for (BasicBlock successor : currentBlock.successors) {

                    if (current.getTrace().contains(successor)) {
                        continue;
                    }

                    BoolExpr branchCondition = computeBranchCondition(currentBlock, successor);
                    BoolExpr newCondition = z3Context.mkAnd(current.getPathCondition(), branchCondition);

                    workList.add(current.extend(successor, newCondition));
                }
            }

            logger.info(String.format("[PathSensitive] Analyzed %d paths in %s.%s",
                    pathsExplored, className, methodNode.name));

        } catch (Exception e) {
            logger.warning("[PathSensitive] Analysis failed: " + e.getMessage());
        }
    }

    private Map<AbstractInsnNode, BasicBlock> buildBasicBlocks(MethodNode methodNode, CFGAnalyzer analyzer) {

        Map<AbstractInsnNode, BasicBlock> blocks = new LinkedHashMap<>();
        if (methodNode.instructions.size() == 0) {
            return blocks;
        }

        for (AbstractInsnNode insn : methodNode.instructions) {
            blocks.put(insn, new BasicBlock(insn));
        }

        for (AbstractInsnNode insn : methodNode.instructions) {
            BasicBlock currentBlock = blocks.get(insn);

            if (insn instanceof JumpInsnNode) {
                JumpInsnNode jump = (JumpInsnNode) insn;
                BasicBlock target = blocks.get(jump.label);
                if (target != null) {
                    currentBlock.successors.add(target);
                    target.predecessors.add(currentBlock);
                }

                if (insn.getOpcode() != Opcodes.GOTO) {
                    if (insn.getNext() != null) {
                        BasicBlock nextBlock = blocks.get(insn.getNext());
                        if (nextBlock != null) {
                            currentBlock.successors.add(nextBlock);
                            nextBlock.predecessors.add(currentBlock);
                        }
                    }
                }
            } else if (insn.getOpcode() != Opcodes.ATHROW &&
                    (insn.getOpcode() < Opcodes.IRETURN || insn.getOpcode() > Opcodes.RETURN)) {

                if (insn.getNext() != null) {
                    BasicBlock nextBlock = blocks.get(insn.getNext());
                    if (nextBlock != null) {
                        currentBlock.successors.add(nextBlock);
                        nextBlock.predecessors.add(currentBlock);
                    }
                }
            }
        }

        return blocks;
    }

    private BoolExpr computeBranchCondition(BasicBlock from, BasicBlock to) {
        AbstractInsnNode insn = from.start;

        if (!(insn instanceof JumpInsnNode)) {

            return z3Context.mkTrue();
        }

        JumpInsnNode jump = (JumpInsnNode) insn;
        boolean takingBranch = jump.label.equals(to.start);

        IntExpr a = z3Context.mkIntConst("v" + System.identityHashCode(insn) + "_a");
        IntExpr b = z3Context.mkIntConst("v" + System.identityHashCode(insn) + "_b");
        Expr<?> ref = z3Context.mkConst("ref" + System.identityHashCode(insn), z3Context.mkUninterpretedSort("Object"));

        BoolExpr condition;

        switch (jump.getOpcode()) {
            case Opcodes.IFEQ:
                condition = z3Context.mkEq(a, z3Context.mkInt(0));
                break;
            case Opcodes.IFNE:
                condition = z3Context.mkNot(z3Context.mkEq(a, z3Context.mkInt(0)));
                break;
            case Opcodes.IFLT:
                condition = z3Context.mkLt(a, z3Context.mkInt(0));
                break;
            case Opcodes.IFGE:
                condition = z3Context.mkGe(a, z3Context.mkInt(0));
                break;
            case Opcodes.IFGT:
                condition = z3Context.mkGt(a, z3Context.mkInt(0));
                break;
            case Opcodes.IFLE:
                condition = z3Context.mkLe(a, z3Context.mkInt(0));
                break;
            case Opcodes.IF_ICMPEQ:
                condition = z3Context.mkEq(a, b);
                break;
            case Opcodes.IF_ICMPNE:
                condition = z3Context.mkNot(z3Context.mkEq(a, b));
                break;
            case Opcodes.IF_ICMPLT:
                condition = z3Context.mkLt(a, b);
                break;
            case Opcodes.IF_ICMPGE:
                condition = z3Context.mkGe(a, b);
                break;
            case Opcodes.IF_ICMPGT:
                condition = z3Context.mkGt(a, b);
                break;
            case Opcodes.IF_ICMPLE:
                condition = z3Context.mkLe(a, b);
                break;
            case Opcodes.IFNULL:

                condition = z3Context.mkTrue();
                break;
            case Opcodes.IFNONNULL:

                condition = z3Context.mkTrue();
                break;
            case Opcodes.GOTO:
                condition = z3Context.mkTrue();
                break;
            default:

                condition = z3Context.mkTrue();
                break;
        }

        if (!takingBranch && jump.getOpcode() != Opcodes.GOTO) {
            condition = z3Context.mkNot(condition);
        }

        return condition;
    }

    private boolean containsDangerousSink(BasicBlock block) {
        AbstractInsnNode insn = block.start;

        if (insn instanceof MethodInsnNode) {
            MethodInsnNode methodInsn = (MethodInsnNode) insn;
            String methodSig = methodInsn.owner + "." + methodInsn.name;

            for (String sink : dangerousSinks) {
                if (methodSig.contains(sink)) {
                    return true;
                }
            }
        }

        return false;
    }

    private boolean isPathSatisfiable(CFGPath path) {
        try {
            Solver solver = z3Context.mkSolver();
            solver.add(path.getPathCondition());

            Status status = solver.check();
            return status == Status.SATISFIABLE;
        } catch (Exception e) {
            logger.warning("[PathSensitive] Z3 check failed: " + e.getMessage());

            return true;
        }
    }

    private void reportVulnerability(CFGPath path, String className, String methodName, Set<String> findings) {
        BasicBlock sinkBlock = path.getCurrentBlock();
        AbstractInsnNode sinkInsn = sinkBlock.start;

        String sinkMethod = "";
        if (sinkInsn instanceof MethodInsnNode) {
            MethodInsnNode methodInsn = (MethodInsnNode) sinkInsn;
            sinkMethod = methodInsn.owner + "." + methodInsn.name;
        }

        String finding = String.format(
                "CRITICAL PATH-SENSITIVE: Dangerous method '%s' is reachable in %s.%s via satisfiable path (length: %d blocks)",
                sinkMethod,
                className.replace('/', '.'),
                methodName,
                path.getLength());

        findings.add(finding);
        logger.info("[PathSensitive] " + finding);
    }

    public void close() {
        if (z3Context != null) {
            z3Context.close();
        }
    }

    private static class CFGPath {
        private final BasicBlock currentBlock;
        private final BoolExpr pathCondition;
        private final List<BasicBlock> trace;

        public CFGPath(BasicBlock currentBlock, BoolExpr pathCondition) {
            this.currentBlock = currentBlock;
            this.pathCondition = pathCondition;
            this.trace = new ArrayList<>();
            this.trace.add(currentBlock);
        }

        public CFGPath(BasicBlock currentBlock, BoolExpr pathCondition, List<BasicBlock> previousTrace) {
            this.currentBlock = currentBlock;
            this.pathCondition = pathCondition;
            this.trace = new ArrayList<>(previousTrace);
            this.trace.add(currentBlock);
        }

        public BasicBlock getCurrentBlock() {
            return currentBlock;
        }

        public BoolExpr getPathCondition() {
            return pathCondition;
        }

        public List<BasicBlock> getTrace() {
            return new ArrayList<>(trace);
        }

        public int getLength() {
            return trace.size();
        }

        public CFGPath extend(BasicBlock successor, BoolExpr newCondition) {
            return new CFGPath(successor, newCondition, this.trace);
        }

        @Override
        public String toString() {
            return "CFGPath{blocks=" + trace.size() + ", condition=" + pathCondition + "}";
        }
    }
}
