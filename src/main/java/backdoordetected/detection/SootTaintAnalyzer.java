package backdoordetected.detection;

import backdoordetected.detection.AbstractTaintInterpreter.AbstractState;
import backdoordetected.detection.AbstractTaintInterpreter.TaintState;
import backdoordetected.models.PluginAnalysisResult;
import backdoordetected.models.SootAnalysisResult;
import backdoordetected.models.TaintFlow;
import backdoordetected.services.PluginAnalyzer;
import backdoordetected.utils.ScanMode;
import backdoordetected.utils.StandaloneLogger;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.*;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.*;

public class SootTaintAnalyzer implements PluginAnalyzer {

  private static final Logger logger = StandaloneLogger.getLogger();
  private static final String ANALYZER_NAME = "SootTaintAnalyzer";

  @Override
  public String getName() {
    return ANALYZER_NAME;
  }

  private static final int ANALYSIS_TIMEOUT_SECONDS = 300;
  private static final int MAX_TAINT_FLOWS = 100;
  private static final int MAX_CALL_DEPTH = 5;

  private final AbstractTaintInterpreter interpreter = new AbstractTaintInterpreter();

  private static final Set<String> TAINT_SOURCE_METHODS = Set.of(
      "onCommand",
      "onPlayerCommand",
      "onTabComplete",
      "onPlayerChat",
      "onPlayerInteract",
      "onPlayerJoin",
      "onPlayerLogin",
      "onPlayerMove",
      "onBlockBreak",
      "getMessage",
      "getArgs",
      "getPlayer",
      "getSender",
      "getName",
      "getDisplayName",
      "getCustomName");

  private static final Set<String> TAINT_SOURCE_TYPES = Set.of(
      "org/bukkit/entity/Player",
      "org/bukkit/command/CommandSender",
      "org/bukkit/event/Event",
      "org/bukkit/command/Command");

  private static final Map<String, String> DANGEROUS_SINKS = Map.ofEntries(
      Map.entry("java/lang/Runtime.exec", "CRITICAL"),
      Map.entry("java/lang/ProcessBuilder.command", "CRITICAL"),
      Map.entry("java/lang/ProcessBuilder.start", "CRITICAL"),
      Map.entry("java/lang/Class.forName", "HIGH"),
      Map.entry("java/lang/reflect/Method.invoke", "HIGH"),
      Map.entry("java/lang/reflect/Constructor.newInstance", "HIGH"),
      Map.entry("java/io/FileWriter.<init>", "MEDIUM"),
      Map.entry("java/io/FileOutputStream.<init>", "MEDIUM"),
      Map.entry("java/nio/file/Files.write", "MEDIUM"),
      Map.entry("java/nio/file/Files.writeString", "MEDIUM"),
      Map.entry("org/bukkit/Server.dispatchCommand", "HIGH"),
      Map.entry("org/bukkit/entity/Player.performCommand", "HIGH"),
      Map.entry("org/bukkit/Bukkit.dispatchCommand", "HIGH"));

  private final Map<String, ClassNode> classCache = new ConcurrentHashMap<>();
  private final TaintConstraintGenerator proofGenerator = new TaintConstraintGenerator();
  private final List<TaintConstraintGenerator.TaintProof> proofs = new ArrayList<>();

  @Override
  public PluginAnalysisResult analyze(
      Path pluginPath,
      List<Path> javaFiles,
      List<Path> classFiles,
      Path workingDir,
      ScanMode scanMode,
      String workerName)
      throws Exception {

    logger.info("[" + workerName + "] Running " + getName() + " for: " + pluginPath.getFileName());

    ExecutorService executor = Executors.newSingleThreadExecutor();
    Future<SootAnalysisResult> future = executor.submit(() -> performAnalysis(pluginPath));

    try {
      SootAnalysisResult result = future.get(ANALYSIS_TIMEOUT_SECONDS, TimeUnit.SECONDS);
      logger.info(
          "["
              + workerName
              + "] "
              + getName()
              + " completed. Found "
              + result.taintFlows().size()
              + " taint flow(s)");

      return result;
    } catch (TimeoutException e) {
      logger.warning(
          "["
              + workerName
              + "] "
              + getName()
              + " timed out after "
              + ANALYSIS_TIMEOUT_SECONDS
              + " seconds");
      future.cancel(true);
      return SootAnalysisResult.withErrors(getName(), List.of("Analysis timeout"));
    } catch (Exception e) {
      logger.severe("[" + workerName + "] " + getName() + " failed: " + e.getMessage());
      return SootAnalysisResult.withErrors(getName(), List.of("Analysis error: " + e.getMessage()));
    } finally {
      executor.shutdownNow();
    }
  }

  private SootAnalysisResult performAnalysis(Path pluginPath) {
    List<TaintFlow> taintFlows = new ArrayList<>();
    List<String> findings = new ArrayList<>();
    List<String> errors = new ArrayList<>();

    try {
      loadClassesFromJar(pluginPath);
      Set<String> taintSources = findTaintSourceMethods();
      logger.info("[Soot] Found " + taintSources.size() + " potential taint source(s)");

      for (String methodKey : taintSources) {
        if (taintFlows.size() >= MAX_TAINT_FLOWS) {
          logger.warning("[Soot] Reached maximum taint flow limit");
          break;
        }

        try {
          List<TaintFlow> flows = analyzeTaintSource(methodKey, 0, new HashSet<>());
          taintFlows.addAll(flows);
        } catch (Exception e) {
          logger.fine("[Soot] Error analyzing " + methodKey + ": " + e.getMessage());
        }
      }

      findings = generateFindings(taintFlows);

      int criticalFlows = (int) taintFlows.stream().filter(f -> "CRITICAL".equals(f.severity())).count();

      if (criticalFlows > 0) {
        logger.info("[Z3] Generating proofs for " + criticalFlows + " CRITICAL taint flow(s)...");

        for (TaintFlow flow : taintFlows) {
          if ("CRITICAL".equals(flow.severity())) {
            try {
              TaintConstraintGenerator.TaintProof proof = proofGenerator.generateProof(flow, pluginPath);

              if (proof != null) {
                proofs.add(proof);

                findings.add(proof.toShortString());

                if (proof.exploitable()) {

                  findings.add(proof.toFormattedString());
                  logger.severe("[Z3] EXPLOITABLE BACKDOOR CONFIRMED: " + flow.sink());
                }
              }
            } catch (Exception e) {
              logger.fine("[Z3] Proof generation failed: " + e.getMessage());
            }
          }
        }

        long exploitableCount = proofs.stream().filter(TaintConstraintGenerator.TaintProof::exploitable).count();

        if (exploitableCount > 0) {
          findings.add(
              0,
              String.format(
                  "[Z3] CRITICAL: %d/%d taint flows are CONFIRMED EXPLOITABLE by Z3 solver",
                  exploitableCount, criticalFlows));
        }
      }

    } catch (Exception e) {
      logger.severe("[Soot] Fatal error: " + e.getMessage());
      errors.add("Fatal error: " + e.getMessage());
    }

    Map<String, List<String>> genericFindings = new HashMap<>();
    if (!findings.isEmpty()) {
      genericFindings.put("findings", findings);
    }

    boolean hasHighSeverity = taintFlows.stream().anyMatch(f -> "CRITICAL".equals(f.severity()));
    boolean hasLowSeverity = !findings.isEmpty() && !hasHighSeverity;

    return new SootAnalysisResult(
        getName(), genericFindings, hasHighSeverity, hasLowSeverity, taintFlows, errors);
  }

  private void loadClassesFromJar(Path jarPath) throws IOException {
    try (JarFile jarFile = new JarFile(jarPath.toFile())) {
      jarFile.stream()
          .filter(entry -> entry.getName().endsWith(".class"))
          .filter(entry -> !entry.getName().startsWith("META-INF/"))
          .forEach(
              entry -> {
                try {
                  loadClass(jarFile, entry);
                } catch (Exception e) {

                }
              });
    }
    logger.info("[Soot] Loaded " + classCache.size() + " class(es) for analysis");
  }

  private void loadClass(JarFile jarFile, JarEntry entry) throws IOException {
    try (InputStream is = jarFile.getInputStream(entry)) {
      ClassReader cr = new ClassReader(is);
      ClassNode cn = new ClassNode();
      cr.accept(cn, ClassReader.SKIP_FRAMES);

      String className = cn.name;
      if (!isLibraryClass(className)) {
        classCache.put(className, cn);
      }
    }
  }

  private Set<String> findTaintSourceMethods() {
    Set<String> sources = new HashSet<>();

    for (ClassNode cn : classCache.values()) {
      for (MethodNode mn : cn.methods) {
        if (TAINT_SOURCE_METHODS.stream().anyMatch(mn.name::contains)) {
          sources.add(cn.name + "." + mn.name + mn.desc);
          continue;
        }

        if (hasEventParameters(mn)) {
          sources.add(cn.name + "." + mn.name + mn.desc);
        }
      }
    }

    return sources;
  }

  private boolean hasEventParameters(MethodNode mn) {
    Type[] argTypes = Type.getArgumentTypes(mn.desc);
    for (Type argType : argTypes) {
      String typeName = argType.getInternalName();
      if (TAINT_SOURCE_TYPES.stream().anyMatch(typeName::contains)) {
        return true;
      }
    }
    return false;
  }

  private List<TaintFlow> analyzeTaintSource(String methodKey, int depth, Set<String> visited) {
    List<TaintFlow> flows = new ArrayList<>();

    if (depth > MAX_CALL_DEPTH || visited.contains(methodKey)) {
      return flows;
    }

    visited.add(methodKey);

    String[] parts = methodKey.split("\\.");
    if (parts.length < 2)
      return flows;

    String className = parts[0];
    String methodDesc = parts[1];

    ClassNode cn = classCache.get(className);
    if (cn == null)
      return flows;

    MethodNode mn = cn.methods.stream()
        .filter(m -> (m.name + m.desc).equals(methodDesc))
        .findFirst()
        .orElse(null);

    if (mn == null)
      return flows;

    AbstractState initialState = new AbstractState();
    int localIndex = 0;

    if ((mn.access & Opcodes.ACC_STATIC) == 0) {
      initialState.setLocal(localIndex++, TaintState.NOT_TAINTED, Collections.emptySet());
    }

    for (Type argType : Type.getArgumentTypes(mn.desc)) {
      initialState.setLocal(localIndex, TaintState.TAINTED, Collections.emptySet());
      localIndex += argType.getSize();
    }

    Map<AbstractInsnNode, AbstractState> states = interpreter.analyze(mn, initialState);

    for (AbstractInsnNode insn : mn.instructions) {
      if (insn instanceof MethodInsnNode) {
        MethodInsnNode methodInsn = (MethodInsnNode) insn;
        String methodSig = methodInsn.owner + "." + methodInsn.name;

        AbstractState state = states.get(insn);
        if (state == null)
          continue;

        for (Map.Entry<String, String> sink : DANGEROUS_SINKS.entrySet()) {
          if (methodSig.contains(sink.getKey())) {
            if (isCallTainted(methodInsn, state)) {
              TaintFlow flow = new TaintFlow(
                  methodKey,
                  sink.getKey(),
                  new ArrayList<>(List.of(methodKey, methodSig)),
                  sink.getValue());
              flows.add(flow);
              logger.warning("[Soot] TAINT FLOW DETECTED: " + methodKey + " -> " + sink.getKey());
            }
          }
        }

        if (methodSig.equals("java/lang/Class.forName")) {
          Set<String> classNames = extractStringConstantsForArgument(methodInsn, state, 0);
          for (String targetClassName : classNames) {
            logger.info(
                "[Soot] Resolved Class.forName target: " + targetClassName + " at " + methodKey);
          }
        }
        if (methodSig.equals("java/lang/reflect/Method.invoke")) {
          logger.fine("[Soot] Detected Method.invoke at " + methodKey);
        }

        if (depth < MAX_CALL_DEPTH && !isLibraryClass(methodInsn.owner)) {

          if (isCallTainted(methodInsn, state)) {
            String targetMethod = methodInsn.owner + "." + methodInsn.name + methodInsn.desc;
            flows.addAll(analyzeTaintSource(targetMethod, depth + 1, new HashSet<>(visited)));
          }
        }
      }
    }

    return flows;
  }

  private Set<String> extractStringConstantsForArgument(
      MethodInsnNode methodInsn, AbstractState state, int argIndex) {
    Type[] argTypes = Type.getArgumentTypes(methodInsn.desc);
    if (argIndex < 0 || argIndex >= argTypes.length) {
      return Collections.emptySet();
    }
    int stackDepth = 0;
    for (int i = argTypes.length - 1; i > argIndex; i--) {
      stackDepth += argTypes[i].getSize();
    }
    if (state.stackSize() > stackDepth) {
      return state.peekStackConstantsAt(stackDepth);
    }

    return Collections.emptySet();
  }

  private boolean isCallTainted(MethodInsnNode methodInsn, AbstractState state) {
    Type[] argTypes = Type.getArgumentTypes(methodInsn.desc);

    AbstractState tempState = new AbstractState(state);
    for (int i = 0; i < argTypes.length; i++) {
      TaintState argTaint = tempState.popStack();
      if (argTaint == TaintState.TAINTED) {
        return true;
      }
    }

    return false;
  }

  private boolean isLibraryClass(String className) {
    return className.startsWith("java/")
        || className.startsWith("javax/")
        || className.startsWith("sun/")
        || className.startsWith("org/bukkit/")
        || className.startsWith("com/google/");
  }

  private List<String> generateFindings(List<TaintFlow> taintFlows) {
    List<String> findings = new ArrayList<>();

    Map<String, Long> severityCounts = taintFlows.stream()
        .collect(Collectors.groupingBy(TaintFlow::severity, Collectors.counting()));

    if (!taintFlows.isEmpty()) {
      findings.add(
          String.format(
              "[Soot] Detected %d taint flow(s) using Abstract Interpretation: %d CRITICAL, %d HIGH, %d MEDIUM",
              taintFlows.size(),
              severityCounts.getOrDefault("CRITICAL", 0L),
              severityCounts.getOrDefault("HIGH", 0L),
              severityCounts.getOrDefault("MEDIUM", 0L)));

      taintFlows.stream()
          .filter(f -> "CRITICAL".equals(f.severity()))
          .limit(5)
          .forEach(flow -> findings.add(flow.toFormattedString()));
    }

    return findings;
  }
}
