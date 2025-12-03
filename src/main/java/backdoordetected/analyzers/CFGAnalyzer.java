package backdoordetected.analyzers;

import java.util.*;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;
import backdoordetected.utils.StandaloneLogger;
import java.util.logging.Logger;

public class CFGAnalyzer {

  private static final Logger logger = StandaloneLogger.getLogger();

  public void analyze(MethodNode methodNode, String className, Set<String> findings) {
    Map<AbstractInsnNode, BasicBlock> blockMap = buildBasicBlocks(methodNode);
    if (blockMap.isEmpty()) {
      return;
    }

    BasicBlock entryBlock = blockMap.get(methodNode.instructions.getFirst());
    if (entryBlock == null)
      return;
    List<BasicBlock> allBlocks = new ArrayList<>(blockMap.values());
    DominatorTree domTree = new DominatorTree(allBlocks, entryBlock);
    detectDeadCode(allBlocks, domTree, className, methodNode.name, findings);
    LoopAnalysis loopAnalysis = new LoopAnalysis(allBlocks, domTree);
    detectDangerousLoops(loopAnalysis, className, methodNode.name, findings);
  }

  private void detectDeadCode(
      List<BasicBlock> allBlocks,
      DominatorTree domTree,
      String className,
      String methodName,
      Set<String> findings) {
    for (BasicBlock block : allBlocks) {
      if (!domTree.isReachable(block)) {
        String finding = String.format(
            "HIGH: Unreachable code detected in class '%s', method '%s'. This could be a hidden payload.",
            className.replace('/', '.'), methodName);
        findings.add(finding);
        break;
      }
    }
  }

  private void detectDangerousLoops(
      LoopAnalysis loopAnalysis, String className, String methodName, Set<String> findings) {
    for (Loop loop : loopAnalysis.getLoops()) {
      if (loop.isInfinite()) {
        findings.add(
            String.format(
                "MEDIUM: Potential infinite loop detected in class '%s', method '%s'. Could be used for DoS.",
                className.replace('/', '.'), methodName));
      }
      if (loop.getDepth() > 3) {
        findings.add(
            String.format(
                "LOW: Deeply nested loop (depth %d) in class '%s', method '%s'. Potential obfuscation or complexity.",
                loop.getDepth(), className.replace('/', '.'), methodName));
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
        BasicBlock target = blocks.get(jump.label);
        if (target != null) {
          currentBlock.successors.add(target);
          target.predecessors.add(currentBlock);
        }
        if (insn.getOpcode() != Opcodes.GOTO) {
          BasicBlock next = blocks.get(insn.getNext());
          if (next != null) {
            currentBlock.successors.add(next);
            next.predecessors.add(currentBlock);
          }
        }
      } else if (insn instanceof TableSwitchInsnNode) {
        TableSwitchInsnNode tableSwitch = (TableSwitchInsnNode) insn;
        BasicBlock dflt = blocks.get(tableSwitch.dflt);
        if (dflt != null) {
          currentBlock.successors.add(dflt);
          dflt.predecessors.add(currentBlock);
        }
        for (LabelNode label : tableSwitch.labels) {
          BasicBlock target = blocks.get(label);
          if (target != null) {
            currentBlock.successors.add(target);
            target.predecessors.add(currentBlock);
          }
        }
      } else if (insn instanceof LookupSwitchInsnNode) {
        LookupSwitchInsnNode lookupSwitch = (LookupSwitchInsnNode) insn;
        BasicBlock dflt = blocks.get(lookupSwitch.dflt);
        if (dflt != null) {
          currentBlock.successors.add(dflt);
          dflt.predecessors.add(currentBlock);
        }
        for (LabelNode label : lookupSwitch.labels) {
          BasicBlock target = blocks.get(label);
          if (target != null) {
            currentBlock.successors.add(target);
            target.predecessors.add(currentBlock);
          }
        }
      } else if (insn.getOpcode() != Opcodes.ATHROW
          && (insn.getOpcode() < Opcodes.IRETURN || insn.getOpcode() > Opcodes.RETURN)) {
        if (insn.getNext() != null) {
          BasicBlock next = blocks.get(insn.getNext());
          if (next != null) {
            currentBlock.successors.add(next);
            next.predecessors.add(currentBlock);
          }
        }
      }
    }
    return blocks;
  }

  public static class BasicBlock {
    public final AbstractInsnNode start;
    public final List<BasicBlock> successors = new ArrayList<>();
    public final List<BasicBlock> predecessors = new ArrayList<>();
    public int id;

    public BasicBlock(AbstractInsnNode start) {
      this.start = start;
    }
  }

  private static class DominatorTree {
    private final Map<BasicBlock, BasicBlock> idom = new HashMap<>();
    private final Set<BasicBlock> reachable = new HashSet<>();

    public DominatorTree(List<BasicBlock> blocks, BasicBlock entry) {
      computeReachable(entry);
      computeDominators(blocks, entry);
    }

    private void computeReachable(BasicBlock entry) {
      Queue<BasicBlock> q = new LinkedList<>();
      q.add(entry);
      reachable.add(entry);
      while (!q.isEmpty()) {
        BasicBlock curr = q.poll();
        for (BasicBlock succ : curr.successors) {
          if (reachable.add(succ)) {
            q.add(succ);
          }
        }
      }
    }

    public boolean isReachable(BasicBlock block) {
      return reachable.contains(block);
    }

    private void computeDominators(List<BasicBlock> blocks, BasicBlock entry) {
      for (BasicBlock b : blocks) {
        if (reachable.contains(b)) {
          idom.put(b, null);
        }
      }
      idom.put(entry, entry);

      boolean changed = true;
      while (changed) {
        changed = false;
        for (BasicBlock b : blocks) {
          if (b == entry || !reachable.contains(b))
            continue;

          BasicBlock newIdom = null;
          for (BasicBlock p : b.predecessors) {
            if (idom.get(p) != null) {
              if (newIdom == null) {
                newIdom = p;
              } else {
                newIdom = intersect(newIdom, p);
              }
            }
          }

          if (newIdom != null && newIdom != idom.get(b)) {
            idom.put(b, newIdom);
            changed = true;
          }
        }
      }
    }

    private BasicBlock intersect(BasicBlock b1, BasicBlock b2) {
      Set<BasicBlock> ancestors1 = new HashSet<>();
      BasicBlock curr = b1;
      while (curr != null && ancestors1.add(curr) && curr != idom.get(curr)) {
        curr = idom.get(curr);
      }
      if (curr != null)
        ancestors1.add(curr);

      curr = b2;
      while (curr != null) {
        if (ancestors1.contains(curr))
          return curr;
        if (curr == idom.get(curr))
          break;
        curr = idom.get(curr);
      }
      return null;
    }

    public BasicBlock getImmediateDominator(BasicBlock block) {
      return idom.get(block);
    }

    public boolean dominates(BasicBlock dom, BasicBlock node) {
      if (dom == node)
        return true;
      BasicBlock curr = node;
      while (curr != null && curr != idom.get(curr)) {
        if (curr == dom)
          return true;
        curr = idom.get(curr);
      }
      return curr == dom;
    }
  }

  private static class LoopAnalysis {
    private final List<Loop> loops = new ArrayList<>();

    public LoopAnalysis(List<BasicBlock> blocks, DominatorTree domTree) {
      for (BasicBlock header : blocks) {
        if (!domTree.isReachable(header))
          continue;
        for (BasicBlock backEdgeSource : header.predecessors) {
          if (domTree.isReachable(backEdgeSource) && domTree.dominates(header, backEdgeSource)) {
            loops.add(new Loop(header, backEdgeSource));
          }
        }
      }
    }

    public List<Loop> getLoops() {
      return loops;
    }
  }

  private static class Loop {
    BasicBlock header;
    BasicBlock backEdgeSource;

    public Loop(BasicBlock header, BasicBlock backEdgeSource) {
      this.header = header;
      this.backEdgeSource = backEdgeSource;
    }

    public boolean isInfinite() {
      if (header.start.getOpcode() == Opcodes.GOTO) {
        JumpInsnNode jump = (JumpInsnNode) header.start;
        return true;
      }
      return false;
    }

    public int getDepth() {
      return 1;
    }
  }

  public InterproceduralCFG buildInterproceduralCFG(List<MethodNode> methods) {
    Map<MethodNode, Map<AbstractInsnNode, BasicBlock>> methodCFGs = new HashMap<>();
    Map<AbstractInsnNode, MethodNode> callSites = new HashMap<>();
    for (MethodNode method : methods) {
      Map<AbstractInsnNode, BasicBlock> cfg = buildBasicBlocks(method);
      methodCFGs.put(method, cfg);
      for (AbstractInsnNode insn : method.instructions) {
        if (insn instanceof MethodInsnNode) {
          callSites.put(insn, method);
        }
      }
    }

    logger.info(String.format(
        "Built inter-procedural CFG: %d methods, %d call sites",
        methods.size(), callSites.size()));

    return new InterproceduralCFG(methodCFGs, callSites);
  }

  public Set<AbstractInsnNode> backwardSlice(
      AbstractInsnNode target,
      Map<AbstractInsnNode, BasicBlock> cfg) {

    Set<AbstractInsnNode> slice = new HashSet<>();
    Queue<BasicBlock> worklist = new LinkedList<>();
    Set<BasicBlock> visited = new HashSet<>();
    BasicBlock targetBlock = cfg.get(target);
    if (targetBlock == null) {
      return slice;
    }
    worklist.add(targetBlock);
    visited.add(targetBlock);
    while (!worklist.isEmpty()) {
      BasicBlock block = worklist.poll();
      slice.add(block.start);
      for (BasicBlock pred : block.predecessors) {
        if (visited.add(pred)) {
          worklist.add(pred);
        }
      }
    }

    return slice;
  }

  public Set<AbstractInsnNode> forwardSlice(
      AbstractInsnNode source,
      Map<AbstractInsnNode, BasicBlock> cfg) {
    Set<AbstractInsnNode> slice = new HashSet<>();
    Queue<BasicBlock> worklist = new LinkedList<>();
    Set<BasicBlock> visited = new HashSet<>();
    BasicBlock sourceBlock = cfg.get(source);
    if (sourceBlock == null) {
      return slice;
    }
    worklist.add(sourceBlock);
    visited.add(sourceBlock);
    while (!worklist.isEmpty()) {
      BasicBlock block = worklist.poll();
      slice.add(block.start);
      for (BasicBlock succ : block.successors) {
        if (visited.add(succ)) {
          worklist.add(succ);
        }
      }
    }

    return slice;
  }

  public static class InterproceduralCFG {
    private final Map<MethodNode, Map<AbstractInsnNode, BasicBlock>> methodCFGs;
    private final Map<AbstractInsnNode, MethodNode> callSites;

    public InterproceduralCFG(
        Map<MethodNode, Map<AbstractInsnNode, BasicBlock>> methodCFGs,
        Map<AbstractInsnNode, MethodNode> callSites) {
      this.methodCFGs = methodCFGs;
      this.callSites = callSites;
    }

    public Map<AbstractInsnNode, BasicBlock> getCFG(MethodNode method) {
      return methodCFGs.get(method);
    }

    public Map<AbstractInsnNode, MethodNode> getCallSites() {
      return callSites;
    }

    public Set<MethodNode> getMethods() {
      return methodCFGs.keySet();
    }
  }
}
