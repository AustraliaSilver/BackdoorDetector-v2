package backdoordetected;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;

import java.util.*;

public class CFGAnalyzer {

    public void analyze(MethodNode methodNode, String className, Set<String> findings) {
        Map<AbstractInsnNode, BasicBlock> blockMap = buildBasicBlocks(methodNode);
        if (blockMap.isEmpty()) {
            return;
        }

        Set<BasicBlock> reachableBlocks = new HashSet<>();
        Queue<BasicBlock> queue = new LinkedList<>();

        BasicBlock entryBlock = blockMap.get(methodNode.instructions.getFirst());
        if (entryBlock != null) {
            queue.add(entryBlock);
            reachableBlocks.add(entryBlock);
        }

        while (!queue.isEmpty()) {
            BasicBlock current = queue.poll();
            for (BasicBlock successor : current.successors) {
                if (reachableBlocks.add(successor)) {
                    queue.add(successor);
                }
            }
        }

        for (BasicBlock block : blockMap.values()) {
            if (!reachableBlocks.contains(block)) {
                String finding = String.format(
                        "HIGH: Unreachable code detected in class '%s', method '%s'. This could be a hidden payload.",
                        className.replace('/', '.'),
                        methodNode.name
                );
                findings.add(finding);
                break;
            }
        }
    }

    private Map<AbstractInsnNode, BasicBlock> buildBasicBlocks(MethodNode methodNode) {
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
                currentBlock.successors.add(blocks.get(jump.label));
                if (insn.getOpcode() != Opcodes.GOTO) {
                    currentBlock.successors.add(blocks.get(insn.getNext()));
                }
            } else if (insn instanceof TableSwitchInsnNode) {
                TableSwitchInsnNode tableSwitch = (TableSwitchInsnNode) insn;
                currentBlock.successors.add(blocks.get(tableSwitch.dflt));
                for (LabelNode label : tableSwitch.labels) {
                    currentBlock.successors.add(blocks.get(label));
                }
            } else if (insn instanceof LookupSwitchInsnNode) {
                LookupSwitchInsnNode lookupSwitch = (LookupSwitchInsnNode) insn;
                currentBlock.successors.add(blocks.get(lookupSwitch.dflt));
                for (LabelNode label : lookupSwitch.labels) {
                    currentBlock.successors.add(blocks.get(label));
                }
            } else if (insn.getOpcode() != Opcodes.ATHROW && insn.getOpcode() < Opcodes.IRETURN || insn.getOpcode() > Opcodes.RETURN) {
                if (insn.getNext() != null) {
                    currentBlock.successors.add(blocks.get(insn.getNext())); 
                }
            }
        }
        return blocks;
    }

    private static class BasicBlock {
        final AbstractInsnNode start;
        final List<BasicBlock> successors = new ArrayList<>();

        BasicBlock(AbstractInsnNode start) {
            this.start = start;
        }
    }
}