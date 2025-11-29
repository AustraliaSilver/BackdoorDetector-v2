package backdoordetected.analyzers;

import backdoordetected.models.BehaviorFingerprint;
import org.objectweb.asm.*;
import org.objectweb.asm.tree.*;
import backdoordetected.utils.StandaloneLogger;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class BytecodeAnalyzer {

    private static final Logger logger = StandaloneLogger.getLogger();

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
        SUSPICIOUS_CALLS.put("java/lang/reflect/Method.invoke",
                "HIGH: Uses reflection, could be hiding malicious calls");
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
            "javax/crypto/Cipher",
            "java/security/MessageDigest",
            "javax/crypto/spec/SecretKeySpec");

    
    private static final int MAX_INVOKE_DYNAMIC_LOGS = 5;
    private static final int MAX_UNREACHABLE_LOGS = 5;

    public List<String> analyze(List<Path> classFiles) {
        logger.info("Analyzing " + classFiles.size() + " class files...");
        List<String> findings = new ArrayList<>();

        
        Map<String, Integer> findingCounts = new HashMap<>();

        for (Path classFile : classFiles) {
            try (InputStream is = Files.newInputStream(classFile)) {
                ClassReader reader = new ClassReader(is);
                ClassNode classNode = new ClassNode();
                reader.accept(classNode, 0);

                analyzeClass(classNode, findings, findingCounts);

            } catch (IOException e) {
                logger.warning("Failed to analyze class file: " + classFile + " - " + e.getMessage());
            }
        }

        
        addSuppressedFindingsSummary(findings, findingCounts);

        return findings;
    }

    private void analyzeClass(ClassNode classNode, List<String> findings, Map<String, Integer> findingCounts) {
        int networkCalls = 0;
        int fileIOCalls = 0;
        int reflectionCalls = 0;
        int cryptoCalls = 0;
        Set<String> domains = new HashSet<>();
        StringBuilder allStrings = new StringBuilder();

        for (MethodNode method : classNode.methods) {
            boolean isUnreachable = false; 

            for (AbstractInsnNode insn : method.instructions) {
                if (insn.getType() == AbstractInsnNode.METHOD_INSN) {
                    MethodInsnNode methodInsn = (MethodInsnNode) insn;
                    String key = methodInsn.owner + "." + methodInsn.name;

                    if (SUSPICIOUS_CALLS.containsKey(key)) {
                        String reason = SUSPICIOUS_CALLS.get(key);
                        findings.add("Suspicious bytecode call to '" + key + "' in class '"
                                + classNode.name.replace('/', '.') + "', method '" + method.name + "'. Reason: "
                                + reason);
                    }

                    if (key.contains("java/net") || key.contains("org/apache/http"))
                        networkCalls++;
                    if (key.contains("java/io") || key.contains("java/nio"))
                        fileIOCalls++;
                    if (key.contains("java/lang/reflect"))
                        reflectionCalls++;
                    if (CRYPTO_PATTERNS.contains(methodInsn.owner)) {
                        cryptoCalls++;
                        logger.info("Cryptographic API usage detected in class '" + classNode.name.replace('/', '.')
                                + "', method '" + method.name + "'. Call to '" + methodInsn.owner.replace('/', '.')
                                + "'.");
                    }

                    
                    if (isReflectionChain(methodInsn)) {
                        findings.add("CRITICAL: Reflection chain detected in class '" + classNode.name.replace('/', '.')
                                + "', method '" + method.name + "'. This could be an obfuscated backdoor.");
                    }

                } else if (insn.getType() == AbstractInsnNode.INVOKE_DYNAMIC_INSN) {
                    String msg = "MEDIUM: InvokeDynamic detected in " + classNode.name.replace('/', '.') + "."
                            + method.name + " - possible obfuscation or lambda";
                    addFindingWithLimit(findings, findingCounts, "INVOKE_DYNAMIC", msg, MAX_INVOKE_DYNAMIC_LOGS);
                } else if (insn.getType() == AbstractInsnNode.LDC_INSN) {
                    LdcInsnNode ldc = (LdcInsnNode) insn;
                    if (ldc.cst instanceof String) {
                        String s = (String) ldc.cst;
                        allStrings.append(s);
                        checkSuspiciousString(s, classNode.name, method.name, findings);
                        extractDomains(s, domains);
                    }
                }
            }

            
            
            
            if (isUnreachable) {
                String msg = "HIGH: Unreachable code detected in class '" + classNode.name.replace('/', '.')
                        + "', method '" + method.name + "'. This could be a hidden payload.";
                addFindingWithLimit(findings, findingCounts, "UNREACHABLE", msg, MAX_UNREACHABLE_LOGS);
            }
        }

        
        double stringEntropy = calculateShannonEntropy(allStrings.toString());
        BehaviorFingerprint fingerprint = new BehaviorFingerprint(
                networkCalls,
                fileIOCalls,
                reflectionCalls,
                cryptoCalls,
                stringEntropy,
                domains);

        if (fingerprint.isSuspicious()) {
            findings.add("HIGH: Suspicious behavioral fingerprint detected in class '"
                    + classNode.name.replace('/', '.') + "'. Details: " + fingerprint.toString());
        }
    }

    private void addFindingWithLimit(List<String> findings, Map<String, Integer> counts, String type, String message,
            int limit) {
        int currentCount = counts.getOrDefault(type, 0);
        if (currentCount < limit) {
            findings.add(message);
        }
        counts.put(type, currentCount + 1);
    }

    private void addSuppressedFindingsSummary(List<String> findings, Map<String, Integer> counts) {
        for (Map.Entry<String, Integer> entry : counts.entrySet()) {
            String type = entry.getKey();
            int count = entry.getValue();
            int limit = type.equals("INVOKE_DYNAMIC") ? MAX_INVOKE_DYNAMIC_LOGS
                    : type.equals("UNREACHABLE") ? MAX_UNREACHABLE_LOGS : 5;

            if (count > limit) {
                findings.add("INFO: ... and " + (count - limit) + " more '" + type + "' findings suppressed.");
            }
        }
    }

    private boolean isReflectionChain(MethodInsnNode insn) {
        return (insn.owner.equals("java/lang/Class") && insn.name.equals("forName")) ||
                (insn.owner.equals("java/lang/reflect/Method") && insn.name.equals("invoke"));
    }

    private void checkSuspiciousString(String s, String className, String methodName, List<String> findings) {
        for (Map.Entry<String, String> entry : SUSPICIOUS_STRING_PATTERNS.entrySet()) {
            if (s.matches(".*" + entry.getKey() + ".*")) {
                
                if (entry.getKey().contains("http")) {
                    if (isSafeDomain(s))
                        continue;
                }

                String truncated = s.length() > 50 ? s.substring(0, 47) + "..." : s;
                findings.add("Suspicious string in class '" + className.replace('/', '.') + "', method '" + methodName
                        + "'. Reason: " + entry.getValue() + " (Contains suspicious string: '" + truncated + "')");
            }
        }
    }

    private boolean isSafeDomain(String url) {
        return url.contains("google.com") || url.contains("github.com") || url.contains("spigotmc.org")
                || url.contains("bstats.org");
    }

    private void extractDomains(String text, Set<String> domains) {
        Pattern pattern = Pattern.compile("(?:https?://|www\\.)([^/\\s]+)");
        Matcher matcher = pattern.matcher(text);
        while (matcher.find()) {
            domains.add(matcher.group(1));
        }
    }

    private double calculateShannonEntropy(String s) {
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