package backdoordetected.analyzers;

import backdoordetected.models.BehaviorFingerprint;
import backdoordetected.models.BytecodeAnalysisResult;
import backdoordetected.models.PluginAnalysisResult;
import backdoordetected.services.PluginAnalyzer;
import backdoordetected.utils.ScanMode;
import backdoordetected.utils.StandaloneLogger;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.objectweb.asm.*;
import org.objectweb.asm.tree.*;

public class BytecodeAnalyzer implements PluginAnalyzer {

  private static final Logger logger = StandaloneLogger.getLogger();
  private static final String ANALYZER_NAME = "BytecodeAnalyzer";

  @Override
  public String getName() {
    return ANALYZER_NAME;
  }

  private static abstract class BytecodeValue {
    public Object getValue() {
      return null;
    }
  }

  private static class ConstantBytecodeValue extends BytecodeValue {
    final Object value;

    ConstantBytecodeValue(Object value) {
      this.value = value;
    }

    @Override
    public Object getValue() {
      return value;
    }

    @Override
    public String toString() {
      return "Constant(" + value + ")";
    }

    @Override
    public boolean equals(Object o) {
      if (this == o)
        return true;
      if (o == null || getClass() != o.getClass())
        return false;
      ConstantBytecodeValue that = (ConstantBytecodeValue) o;
      return Objects.equals(value, that.value);
    }

    @Override
    public int hashCode() {
      return Objects.hash(value);
    }
  }

  private static class TaintedBytecodeValue extends BytecodeValue {
    final String source;
    final int line;

    TaintedBytecodeValue(String source, int line) {
      this.source = source;
      this.line = line;
    }

    public String getSource() {
      return source;
    }

    public int getLine() {
      return line;
    }

    @Override
    public String toString() {
      return "Tainted(" + source + ", line " + line + ")";
    }

    @Override
    public boolean equals(Object o) {
      if (this == o)
        return true;
      if (o == null || getClass() != o.getClass())
        return false;
      TaintedBytecodeValue that = (TaintedBytecodeValue) o;
      return line == that.line && Objects.equals(source, that.source);
    }

    @Override
    public int hashCode() {
      return Objects.hash(source, line);
    }
  }

  private static final Map<String, String> SUSPICIOUS_CALLS = new HashMap<>();

  static {
    SUSPICIOUS_CALLS.put("java/lang/Runtime.exec", "CRITICAL: Executes system commands");
    SUSPICIOUS_CALLS.put("java/lang/ProcessBuilder.start", "CRITICAL: Executes system commands");
    SUSPICIOUS_CALLS.put("java/lang/ProcessBuilder.command", "CRITICAL: Executes system commands");
    SUSPICIOUS_CALLS.put("java/net/URL.openConnection", "HIGH: Creates network connections");
    SUSPICIOUS_CALLS.put("java/net/Socket.<init>", "HIGH: Creates raw socket connections");
    SUSPICIOUS_CALLS.put("org/bukkit/Bukkit.dispatchCommand", "HIGH: Dispatches a command as the console");
    SUSPICIOUS_CALLS.put("org/bukkit/Server.dispatchCommand", "HIGH: Dispatches a command as the console");
    SUSPICIOUS_CALLS.put("org/bukkit/entity/Player.setOp", "CRITICAL: Grants operator status to a player");
    SUSPICIOUS_CALLS.put("org/bukkit/permissions/Permissible.addAttachment", "HIGH: Modifies permissions");
    SUSPICIOUS_CALLS.put("java/lang/reflect/Method.invoke", "HIGH: Uses reflection, could be hiding malicious calls");
    SUSPICIOUS_CALLS.put("java/lang/Class.forName", "HIGH: Dynamic class loading, often used for obfuscation");
    SUSPICIOUS_CALLS.put("java/lang/ClassLoader.defineClass",
        "CRITICAL: Custom class loading, typical of malware loaders");
    SUSPICIOUS_CALLS.put("org/bukkit/Bukkit.getOnlinePlayers", "LOW: Can be used for targeting players");
    SUSPICIOUS_CALLS.put("org/bukkit/Bukkit.getServer",
        "LOW: General server access, but can be part of malicious chain");
    SUSPICIOUS_CALLS.put("org/bukkit/Bukkit.getPluginManager", "LOW: Can be used to access other plugins");
    SUSPICIOUS_CALLS.put("org/bukkit/scheduler/BukkitScheduler.runTaskTimer",
        "LOW: Schedules repeating tasks, can be used for malicious loops");
  }

  private static final Map<String, String> SUSPICIOUS_STRING_PATTERNS = new HashMap<>();

  static {
    SUSPICIOUS_STRING_PATTERNS.put("(?i)curl\\s+.*", "Contains 'curl' command");
    SUSPICIOUS_STRING_PATTERNS.put("(?i)wget\\s+.*", "Contains 'wget' command");
    SUSPICIOUS_STRING_PATTERNS.put("(?i)rm\\s+-rf.*", "Contains destructive 'rm -rf' command");
    SUSPICIOUS_STRING_PATTERNS.put("(?i)cmd\\.exe", "Targeting Windows command prompt");
    SUSPICIOUS_STRING_PATTERNS.put("(?i)/bin/sh", "Targeting Unix shell");
    SUSPICIOUS_STRING_PATTERNS.put("(?i)/bin/bash", "Targeting Bash shell");
    SUSPICIOUS_STRING_PATTERNS.put("(?i)nc\\s+.*", "Contains 'netcat' command (often used for reverse shells)");
    SUSPICIOUS_STRING_PATTERNS.put("(?i)eval\\(.*\\)", "Contains 'eval()' (dangerous in many languages)");
    SUSPICIOUS_STRING_PATTERNS.put("(?i)base64_decode", "Contains 'base64_decode' (PHP-like signature)");
    SUSPICIOUS_STRING_PATTERNS.put("(?i)http://", "Contains URL prefix 'http://' or 'https://'");
    SUSPICIOUS_STRING_PATTERNS.put("(?i)https://", "Contains URL prefix 'http://' or 'https://'");
    SUSPICIOUS_STRING_PATTERNS.put("(?i)\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}", "Contains an IP address");
  }

  private static final Set<String> CRYPTO_PATTERNS = Set.of(
      "javax/crypto/Cipher", "java/security/MessageDigest", "javax/crypto/spec/SecretKeySpec");

  private static final int MAX_INVOKE_DYNAMIC_LOGS = 5;
  private static final int MAX_UNREACHABLE_LOGS = 5;

  private static class CustomClassAnalyzer extends ClassVisitor {
    private final List<String> findings;
    private final Map<String, Integer> findingCounts;
    private final Set<String> domains;
    private final StringBuilder allStrings;
    private String currentClassName;
    public int networkCalls = 0;
    public int fileIOCalls = 0;
    public int reflectionCalls = 0;
    public int cryptoCalls = 0;

    public CustomClassAnalyzer(
        ClassVisitor api,
        List<String> findings,
        Map<String, Integer> findingCounts,
        Set<String> domains,
        StringBuilder allStrings) {
      super(Opcodes.ASM9, api);
      this.findings = findings;
      this.findingCounts = findingCounts;
      this.domains = domains;
      this.allStrings = allStrings;
    }

    @Override
    public void visit(
        int version,
        int access,
        String name,
        String signature,
        String superName,
        String[] interfaces) {
      super.visit(version, access, name, signature, superName, interfaces);
      this.currentClassName = name;
    }

    @Override
    public MethodVisitor visitMethod(
        int access, String name, String descriptor, String signature, String[] exceptions) {
      MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
      
      return new BytecodeMethodAnalyzer(
          mv, currentClassName, name, descriptor, findings, findingCounts, domains, allStrings, this); 
    }
  }
  private static class BytecodeMethodAnalyzer extends MethodVisitor { 
    private final String className;
    private final String methodName;
    private final String methodDescriptor;
    private final List<String> findings;
    private final Map<String, Integer> findingCounts;
    private final Set<String> domains;
    private final StringBuilder allStrings; 
    private final CustomClassAnalyzer classAnalyzer; 

    private final List<BytecodeValue> operandStack = new ArrayList<>();
    private final Map<Integer, BytecodeValue> localVariables = new HashMap<>();

    private int lastLineNumber = -1;

    public BytecodeMethodAnalyzer(
        MethodVisitor api,
        String className,
        String methodName,
        String methodDescriptor,
        List<String> findings,
        Map<String, Integer> findingCounts,
        Set<String> domains,
        StringBuilder allStrings,
        CustomClassAnalyzer classAnalyzer) {
      super(Opcodes.ASM9, api);
      this.className = className;
      this.methodName = methodName;
      this.methodDescriptor = methodDescriptor;
      this.findings = findings;
      this.findingCounts = findingCounts;
      this.domains = domains;
      this.allStrings = allStrings;
      this.classAnalyzer = classAnalyzer;
    }

    @Override
    public void visitLineNumber(int line, Label start) {
      super.visitLineNumber(line, start);
      this.lastLineNumber = line;
    }

    @Override
    public void visitLdcInsn(Object value) {
      super.visitLdcInsn(value);
      operandStack.add(new ConstantBytecodeValue(value));
      if (value instanceof String) {
        allStrings.append((String) value).append(" "); 
        BytecodeAnalyzer.checkSuspiciousString((String) value, className, methodName, findings); 
        BytecodeAnalyzer.extractDomains((String) value, domains);
      }
    }

    @Override
    public void visitVarInsn(int opcode, int varIndex) {
      super.visitVarInsn(opcode, varIndex);
      if (opcode >= Opcodes.ILOAD && opcode <= Opcodes.ALOAD) {
        operandStack.add(
            localVariables.getOrDefault(varIndex, new TaintedBytecodeValue("Local Var " + varIndex, lastLineNumber)));
      } else if (opcode >= Opcodes.ISTORE && opcode <= Opcodes.ASTORE) {
        if (!operandStack.isEmpty()) {
          localVariables.put(varIndex, popStack());
        }
      }
    }

    @Override
    public void visitFieldInsn(int opcode, String owner, String name, String descriptor) {
      super.visitFieldInsn(opcode, owner, name, descriptor);
      if (opcode == Opcodes.GETSTATIC || opcode == Opcodes.GETFIELD) {
        operandStack.add(new TaintedBytecodeValue("Field " + owner + "." + name, lastLineNumber));
      } else if (opcode == Opcodes.PUTSTATIC || opcode == Opcodes.PUTFIELD) {
        popStack(); 
        if (opcode == Opcodes.PUTFIELD)
          popStack(); 
      }
    }

    @Override
    public void visitInsn(int opcode) {
      super.visitInsn(opcode);
      switch (opcode) {
        case Opcodes.DUP:
          if (!operandStack.isEmpty()) {
            operandStack.add(operandStack.get(operandStack.size() - 1));
          }
          break;
        case Opcodes.SWAP:
          if (operandStack.size() >= 2) {
            BytecodeValue val1 = popStack();
            BytecodeValue val2 = popStack();
            operandStack.add(val1);
            operandStack.add(val2);
          }
          break;
        case Opcodes.POP:
          popStack();
          break;
        default:
          break;
      }
    }
    @Override
    public void visitMethodInsn(
        int opcode, String owner, String name, String descriptor, boolean isInterface) {
      super.visitMethodInsn(opcode, owner, name, descriptor, isInterface);
      String key = owner + "." + name;
      Type methodType = Type.getMethodType(descriptor);
      int argCount = methodType.getArgumentTypes().length;
      int stackConsumed = argCount + (opcode != Opcodes.INVOKESTATIC ? 1 : 0);
      List<BytecodeValue> consumedValues = new ArrayList<>();
      if (operandStack.size() >= stackConsumed) {
        for (int i = 0; i < stackConsumed; i++) {
          consumedValues.add(0, operandStack.get(operandStack.size() - stackConsumed + i));
        }
      } else {
        for (int i = 0; i < stackConsumed; i++)
          consumedValues.add(0, new TaintedBytecodeValue("Stack underflow before method call: " + key, lastLineNumber));
      }

      for (int i = 0; i < stackConsumed; i++) {
        popStack();
      }

      BytecodeValue methodResult = null;

      if (key.equals("java/lang/String.concat") && consumedValues.size() >= 2) {
        BytecodeValue receiver = consumedValues.get(0);
        BytecodeValue arg = consumedValues.get(1); 

        if (receiver instanceof ConstantBytecodeValue && receiver.getValue() instanceof String &&
            arg instanceof ConstantBytecodeValue && arg.getValue() instanceof String) {
          String resultString = (String) arg.getValue() + (String) receiver.getValue();
          methodResult = new ConstantBytecodeValue(resultString);
        }
      }
      if (methodType.getReturnType() != Type.VOID_TYPE) {
        if (methodResult != null) {
          operandStack.add(methodResult);
        } else {
          boolean anyArgTainted = consumedValues.stream().anyMatch(v -> v instanceof TaintedBytecodeValue);
          if (anyArgTainted) {
            operandStack.add(new TaintedBytecodeValue("Method result (taint propagated): " + key, lastLineNumber));
          } else {
            operandStack.add(new TaintedBytecodeValue("Method result: " + key, lastLineNumber));
          }
        }
      }

      if (SUSPICIOUS_CALLS.containsKey(key)) {
        String reason = SUSPICIOUS_CALLS.get(key);
        findings.add(
            "Suspicious bytecode call to '"
                + key
                + "' in class '"
                + className.replace('/', '.')
                + "', method '"
                + methodName
                + "'. Reason: "
                + reason);
      }

      if (key.contains("java/net") || key.contains("org/apache/http"))
        classAnalyzer.networkCalls++;
      if (key.contains("java/io") || key.contains("java/nio"))
        classAnalyzer.fileIOCalls++;
      if (key.contains("java/lang/reflect"))
        classAnalyzer.reflectionCalls++;
      if (CRYPTO_PATTERNS.contains(owner)) {
        classAnalyzer.cryptoCalls++;
      }
      if (key.equals("java/lang/Class.forName")) {
        BytecodeValue classForNameArg = null;
        if (!consumedValues.isEmpty()) { 
          classForNameArg = consumedValues.get(0);
        }

        if (classForNameArg instanceof ConstantBytecodeValue && classForNameArg.getValue() instanceof String) {
          String resolvedClassName = (String) ((ConstantBytecodeValue) classForNameArg).getValue();
          if (resolvedClassName.equals("java.lang.Runtime")) {
            findings.add("CRITICAL REFLECTION: Class.forName(\"" + resolvedClassName
                + "\") resolved from constant string at line " + lastLineNumber);
          }
        } else if (classForNameArg instanceof TaintedBytecodeValue) {
          findings.add("CRITICAL REFLECTION: Class.forName called with tainted class name at line " + lastLineNumber
              + ". Source: " + ((TaintedBytecodeValue) classForNameArg).getSource());
        } else {
          findings.add("CRITICAL REFLECTION: Class.forName called with unknown/non-constant argument at line "
              + lastLineNumber + ". Arg: " + (classForNameArg != null ? classForNameArg.toString() : "null"));
        }
      }
      if (key.equals("java/lang/reflect/Method.invoke") || key.equals("java/lang/Class.forName")) {
        findings.add(
            "CRITICAL: Reflection chain detected (Method.invoke or Class.forName) in class '"
                + className.replace('/', '.')
                + "', method '"
                + methodName
                + "'. This could be an obfuscated backdoor.");
      }
    }

    private BytecodeValue popStack() {
      if (operandStack.isEmpty()) {
        return new TaintedBytecodeValue("Stack underflow/unknown", lastLineNumber);
      }
      return operandStack.remove(operandStack.size() - 1);
    }

    private List<BytecodeValue> getArguments(int count, boolean remove) {
      List<BytecodeValue> args = new ArrayList<>();
      if (operandStack.size() < count) {
        for (int i = 0; i < count; i++)
          args.add(new TaintedBytecodeValue("Missing arg on stack", lastLineNumber));
        if (remove)
          operandStack.clear(); 
        return args;
      } else {
        for (int i = 0; i < count; i++) {
          args.add(0, operandStack.get(operandStack.size() - count + i));
        }
        if (remove) {
          operandStack.subList(operandStack.size() - count, operandStack.size()).clear();
        }
      }
      return args;
    }
  }
  public PluginAnalysisResult analyze(
      Path pluginPath,
      List<Path> javaFiles,
      List<Path> classFiles,
      Path workingDir,
      ScanMode scanMode,
      String workerName)
      throws Exception {
    logger.info("Analyzing " + classFiles.size() + " class files...");
    List<String> findings = new ArrayList<>();

    Map<String, Integer> findingCounts = new HashMap<>();
    Set<String> domains = new HashSet<>();
    StringBuilder allStrings = new StringBuilder(); 

    CustomClassAnalyzer classAnalyzer = null; 

    for (Path classFile : classFiles) {
      try (InputStream is = Files.newInputStream(classFile)) {
        ClassReader reader = new ClassReader(is);

        classAnalyzer = new CustomClassAnalyzer(null, findings, findingCounts, domains, allStrings); 
        reader.accept(classAnalyzer, ClassReader.EXPAND_FRAMES);

      } catch (IOException e) {
        logger.warning("Failed to analyze class file: " + classFile + " - " + e.getMessage());
      }
    }

    double stringEntropy = calculateShannonEntropy(allStrings.toString());
    BehaviorFingerprint fingerprint;
    if (classAnalyzer != null) { 
      fingerprint = new BehaviorFingerprint(
          classAnalyzer.networkCalls, classAnalyzer.fileIOCalls, classAnalyzer.reflectionCalls,
          classAnalyzer.cryptoCalls, stringEntropy, domains);
    } else {
      fingerprint = new BehaviorFingerprint(0, 0, 0, 0, stringEntropy, domains);
    }

    if (fingerprint.isSuspicious()) {
      findings.add(
          "HIGH: Suspicious behavioral fingerprint detected. Details: " + fingerprint.toString());
    }

    addSuppressedFindingsSummary(findings, findingCounts);

    boolean hasHighSeverity = false;
    boolean hasLowSeverity = false;
    Map<String, List<String>> genericFindings = new HashMap<>();
    genericFindings.put("rawFindings", new ArrayList<>(findings)); 

    for (String finding : findings) {
      String upperFinding = finding.toUpperCase();
      if (upperFinding.startsWith("CRITICAL:") || upperFinding.startsWith("HIGH:")) {
        hasHighSeverity = true;
      } else if (upperFinding.startsWith("LOW:") || upperFinding.startsWith("MEDIUM:")) {
        hasLowSeverity = true;
      }
    }

    return new BytecodeAnalysisResult(
        getName(), genericFindings, hasHighSeverity, hasLowSeverity, findings);
  }

  private static void addFindingWithLimit( 
      List<String> findings, Map<String, Integer> counts, String type, String message, int limit) {
    int currentCount = counts.getOrDefault(type, 0);
    if (currentCount < limit) {
      findings.add(message);
    }
    counts.put(type, currentCount + 1);
  }

  private static void addSuppressedFindingsSummary(List<String> findings, Map<String, Integer> counts) { 
    for (Map.Entry<String, Integer> entry : counts.entrySet()) {
      String type = entry.getKey();
      int count = entry.getValue();
      int limit = type.equals("INVOKE_DYNAMIC")
          ? MAX_INVOKE_DYNAMIC_LOGS
          : type.equals("UNREACHABLE") ? MAX_UNREACHABLE_LOGS : 5;

      if (count > limit) {
        findings.add(
            "INFO: ... and " + (count - limit) + " more '" + type + "' findings suppressed.");
      }
    }
  }

  private static void checkSuspiciousString( 
      String s, String className, String methodName, List<String> findings) {
    for (Map.Entry<String, String> entry : SUSPICIOUS_STRING_PATTERNS.entrySet()) {
      
      Pattern pattern = Pattern.compile(".*" + entry.getKey() + ".*", Pattern.CASE_INSENSITIVE);
      if (pattern.matcher(s).matches()) {
        if (entry.getKey().contains("http")) {
          if (isSafeDomain(s))
            continue;
        }

        String truncated = s.length() > 50 ? s.substring(0, 47) + "..." : s;
        findings.add(
            "Suspicious string in class "
                + className.replace('/', '.')
                + ", method "
                + methodName
                + ". Reason: "
                + entry.getValue()
                + " (Contains suspicious string: '"
                + truncated
                + "')");
      }
    }
  }

  private static boolean isSafeDomain(String url) {
    return url.contains("google.com")
        || url.contains("github.com")
        || url.contains("spigotmc.org")
        || url.contains("bstats.org");
  }

  private static void extractDomains(String text, Set<String> domains) {
    Pattern pattern = Pattern.compile("(?:https?://|www\\.)([^/\\s]+)");
    Matcher matcher = pattern.matcher(text);
    while (matcher.find()) {
      domains.add(matcher.group(1));
    }
  }

  private static double calculateShannonEntropy(String s) {
    if (s == null || s.isEmpty()) {
      return 0.0;
    }
    Map<Character, Integer> counts = new HashMap<>();
    for (char c : s.toCharArray()) {
      counts.put(c, counts.getOrDefault(c, 0) + 1);
    }
    double entropy = 0.0;
    for (int count : counts.values()) {
      double probability = (double) count / s.length();
      entropy -= probability * (Math.log(probability) / Math.log(2));
    }
    return entropy;
  }
}
