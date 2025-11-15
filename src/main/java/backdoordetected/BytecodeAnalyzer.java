package backdoordetected;

import org.objectweb.asm.*;
import org.objectweb.asm.tree.*;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.regex.Matcher;
import java.util.*;
import java.util.logging.Logger;
import java.util.regex.Pattern;

public class BytecodeAnalyzer {

    private static final Logger logger = StandaloneLogger.getLogger();

    private static final Map<String, String> SUSPICIOUS_CALLS = new HashMap<>();
    private static final Set<String> NETWORK_CALL_PATTERNS = new HashSet<>();
    private static final Map<Pattern, String> SUSPICIOUS_STRING_PATTERNS = new LinkedHashMap<>();

    private static final Set<String> IGNORED_PACKAGE_PREFIXES = Set.of(
            "fr/xephi/authme/libs/", 
            "com/mysql/",
            "org/postgresql/",
            "org/sqlite/",
            "com/zaxxer/hikari/",
            "org/mariadb/jdbc/",
            "com/google/gson/",
            "org/yaml/snakeyaml/",
            "com/sun/jna/" 
    );

    static {
        SUSPICIOUS_CALLS.put("java/lang/Runtime.exec", "CRITICAL: Executes system commands");
        SUSPICIOUS_CALLS.put("java/lang/ProcessBuilder.start", "CRITICAL: Starts a system process");
        SUSPICIOUS_CALLS.put("java/lang/reflect/Method.invoke", "HIGH: Uses reflection, could be hiding malicious calls");
        SUSPICIOUS_CALLS.put("java/net/URL.openConnection", "HIGH: Creates network connections");
        SUSPICIOUS_CALLS.put("java/net/Socket.<init>", "HIGH: Creates a raw socket connection");
        SUSPICIOUS_CALLS.put("java/lang/ClassLoader.defineClass", "CRITICAL: Loads a class from bytes, potential for dynamic code execution");
        SUSPICIOUS_CALLS.put("java/lang/System.load", "CRITICAL: Loads a native library");
        SUSPICIOUS_CALLS.put("org/bukkit/Bukkit.dispatchCommand", "HIGH: Dispatches a command as the console");
        SUSPICIOUS_CALLS.put("org/bukkit/Bukkit.getOfflinePlayer", "LOW: Can be used for UUID impersonation");
        SUSPICIOUS_CALLS.put("org/bukkit/Bukkit.getWhitelistedPlayers", "LOW: Can be used to check for whitelisting");
        SUSPICIOUS_CALLS.put("org/bukkit/Bukkit.getServer", "LOW: General server access, but can be part of malicious chain");
        SUSPICIOUS_CALLS.put("org/bukkit/Bukkit.getOnlinePlayers", "LOW: Can be used for targeting players");
        SUSPICIOUS_CALLS.put("org/bukkit/Bukkit.broadcast", "LOW: Broadcasts messages, could be used for spam");
        SUSPICIOUS_CALLS.put("org/bukkit/Bukkit.broadcastMessage", "LOW: Broadcasts messages, could be used for spam");
        SUSPICIOUS_CALLS.put("org/bukkit/Bukkit.getPluginManager", "LOW: Can be used to access other plugins");
        SUSPICIOUS_CALLS.put("org/bukkit/scheduler/BukkitScheduler.runTaskTimer", "LOW: Schedules repeating tasks, can be used for malicious loops");
        NETWORK_CALL_PATTERNS.add("java/net/URL");
        NETWORK_CALL_PATTERNS.add("java/net/Socket");
        NETWORK_CALL_PATTERNS.add("java/net/HttpURLConnection");
        NETWORK_CALL_PATTERNS.add("org/apache/http/client/HttpClient");
        SUSPICIOUS_STRING_PATTERNS.put(Pattern.compile("\\brce\\b", Pattern.CASE_INSENSITIVE), "Contains exact word 'rce'");
        SUSPICIOUS_STRING_PATTERNS.put(Pattern.compile("\\bkeylogger\\b", Pattern.CASE_INSENSITIVE), "Contains exact word 'keylogger'");
        SUSPICIOUS_STRING_PATTERNS.put(Pattern.compile("backdoor", Pattern.CASE_INSENSITIVE), "Contains 'backdoor'");
        SUSPICIOUS_STRING_PATTERNS.put(Pattern.compile("pastebin\\.com", Pattern.CASE_INSENSITIVE), "Contains URL 'pastebin.com'");
        SUSPICIOUS_STRING_PATTERNS.put(Pattern.compile("https?://", Pattern.CASE_INSENSITIVE), "Contains URL prefix 'http://' or 'https://'");
        SUSPICIOUS_STRING_PATTERNS.put(Pattern.compile("discordapp\\.com/api/webhooks", Pattern.CASE_INSENSITIVE), "Contains Discord webhook URL");
        SUSPICIOUS_STRING_PATTERNS.put(Pattern.compile("new byte\\[\\]\\s*\\{([\\s,0-9\\-]*)\\}"), "MEDIUM: Potential obfuscated string (byte array initialization)");
        SUSPICIOUS_STRING_PATTERNS.put(Pattern.compile("new char\\[\\]\\s*\\{([\\s,0-9']*)\\}"), "MEDIUM: Potential obfuscated string (char array initialization)");
        SUSPICIOUS_STRING_PATTERNS.put(Pattern.compile("remoteaccess", Pattern.CASE_INSENSITIVE), "Contains 'remoteaccess'");
    }

    private static final Set<String> CRYPTO_PATTERNS = Set.of(
            "javax/crypto/Cipher",
            "java/security/MessageDigest",
            "decrypt",
            "decipher"
    );

    private static final Set<String> KNOWN_SUSPICIOUS_KEYS_HEX = Set.of(
        "2b7e151628aed2a6abf7158809cf4f3c", 
        "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
    );
    private static final Set<String> KNOWN_SUSPICIOUS_KEYS_BASE64 = Set.of(
        "K34VFigK7aartxWICc9PPw==", 
        "YD3rEBXKe+4rc67whX13gR81LAd7YQjXLZgQowkU3/Q=" 
    );



    private final CFGAnalyzer cfgAnalyzer = new CFGAnalyzer();
    private final SymbolicExecutor symbolicExecutor = new SymbolicExecutor();

    public List<String> analyze(List<Path> classFiles) {
        Set<String> findings = new HashSet<>(); 
        for (Path classFile : classFiles) {
            try (InputStream is = Files.newInputStream(classFile)) {
                ClassReader cr = new ClassReader(is);
                ClassNode cn = new ClassNode();
                cr.accept(cn, ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES); 

                if (isIgnoredPackage(cn.name)) {
                    logger.fine("Skipping analysis for known library class: " + cn.name);
                    continue; 
                }

                for (MethodNode mn : cn.methods) {
                    analyzeMethod(mn, cn.name, findings);
                }
                analyzeReflectionChain(cn, findings);
                analyzeSymbolicExecution(cn, findings);
                analyzeBehavioralFingerprint(cn, findings);

            } catch (IOException e) {
                logger.log(java.util.logging.Level.WARNING, "Failed to analyze class file: " + classFile.getFileName(), e);
            }
        }
        return new ArrayList<>(findings);
    }

    private boolean isIgnoredPackage(String className) {
        return IGNORED_PACKAGE_PREFIXES.stream().anyMatch(className::startsWith);
    }

    private void analyzeMethod(MethodNode methodNode, String className, Set<String> findings) {
        InsnList instructions = methodNode.instructions;
        for (AbstractInsnNode insnNode : instructions) {
            if (insnNode.getType() == AbstractInsnNode.METHOD_INSN) {
                MethodInsnNode methodInsn = (MethodInsnNode) insnNode;
                String fullMethodSignature = methodInsn.owner + "." + methodInsn.name;
                if (SUSPICIOUS_CALLS.containsKey(fullMethodSignature)) {
                    String finding = String.format(
                            "Suspicious bytecode call to '%s' in class '%s', method '%s'. Reason: %s",
                            fullMethodSignature.replace('/', '.'),
                            className.replace('/', '.'),
                            methodNode.name,
                            SUSPICIOUS_CALLS.get(fullMethodSignature)
                    );
                    findings.add(finding);
                }
                detectCryptoUsage(methodNode, className, findings);
                analyzeInvokeDynamic(methodNode, className, findings);
                cfgAnalyzer.analyze(methodNode, className, findings);
            }
            else if (insnNode.getType() == AbstractInsnNode.LDC_INSN) {
                LdcInsnNode ldcInsn = (LdcInsnNode) insnNode;
                if (ldcInsn.cst instanceof String) {
                    String stringValue = (String) ldcInsn.cst;
                    checkForSuspiciousStrings(stringValue, "Contains suspicious string", className, methodNode.name, findings);
                    if (KNOWN_SUSPICIOUS_KEYS_HEX.contains(stringValue.toLowerCase())) {
                        findings.add(String.format("CRITICAL: Hardcoded known cryptographic key (HEX) detected in class '%s', method '%s'.",
                                className.replace('/', '.'), methodNode.name));
                    }

                    if (isBase64(stringValue)) {
                        try {
                            byte[] decodedBytes = Base64.getDecoder().decode(stringValue.trim());
                            String decodedString = new String(decodedBytes, StandardCharsets.UTF_8);
                            checkForSuspiciousStrings(decodedString, "Contains suspicious DECODED Base64 string", className, methodNode.name, findings);

                            if (KNOWN_SUSPICIOUS_KEYS_BASE64.contains(stringValue)) { 
                                findings.add(String.format("CRITICAL: Hardcoded known cryptographic key (Base64) detected in class '%s', method '%s'.",
                                        className.replace('/', '.'), methodNode.name));
                            }
                            String decodedHex = bytesToHex(decodedBytes);
                            if (KNOWN_SUSPICIOUS_KEYS_HEX.contains(decodedHex)) {
                                findings.add(String.format("CRITICAL: Hardcoded known cryptographic key (decoded Base64 to HEX) detected in class '%s', method '%s'.",
                                        className.replace('/', '.'), methodNode.name));
                            }
                        } catch (IllegalArgumentException e) {
                        }
                    }
                }
            }
        }
    }

    private void analyzeInvokeDynamic(MethodNode mn, String className, Set<String> findings) {
        for (AbstractInsnNode insn : mn.instructions) {
            if (insn.getType() == AbstractInsnNode.INVOKE_DYNAMIC_INSN) {
                InvokeDynamicInsnNode indy = (InvokeDynamicInsnNode) insn;
                findings.add(String.format(
                    "MEDIUM: InvokeDynamic detected in %s.%s - possible obfuscation or lambda",
                    className.replace('/', '.'), mn.name
                ));
            }
        }
    }


    private void detectCryptoUsage(MethodNode mn, String className, Set<String> findings) {
        for (AbstractInsnNode insn : mn.instructions) {
            if (insn.getType() == AbstractInsnNode.METHOD_INSN) {
                MethodInsnNode methodInsn = (MethodInsnNode) insn;
                if (CRYPTO_PATTERNS.contains(methodInsn.owner)) {
                    String finding = String.format(
                            "INFO: Cryptographic API usage detected in class '%s', method '%s'. Call to '%s'.",
                            className.replace('/', '.'), mn.name, methodInsn.owner.replace('/', '.')
                    );
                    findings.add(finding);
                }
                String lowerCaseMethodName = methodInsn.name.toLowerCase();
                if (CRYPTO_PATTERNS.stream().anyMatch(lowerCaseMethodName::contains)) {
                    String finding = String.format(
                            "INFO: Potential crypto activity in class '%s', method '%s'. Method name contains crypto-related keyword: '%s'.",
                            className.replace('/', '.'), mn.name, methodInsn.name
                    );
                    findings.add(finding);
                }
            }
        }
    }

    private void checkForSuspiciousStrings(String text, String reasonPrefix, String className, String methodName, Set<String> findings) {
        for (Map.Entry<Pattern, String> entry : SUSPICIOUS_STRING_PATTERNS.entrySet()) {
            if (entry.getKey().matcher(text).find()) {
                String finding = String.format(
                        "Suspicious string in class '%s', method '%s'. Reason: %s (%s: '%s')",
                        className.replace('/', '.'), methodName, entry.getValue(), reasonPrefix, text.substring(0, Math.min(text.length(), 50)) + "..."
                );
                findings.add(finding);
            }
        }
    }

    private void analyzeReflectionChain(ClassNode cn, Set<String> findings) {
        for (MethodNode mn : cn.methods) {
            List<AbstractInsnNode> reflectionChain = new ArrayList<>();
            for (AbstractInsnNode insn : mn.instructions) {
                if (isReflectionCall(insn)) {
                    reflectionChain.add(insn);
                }
            }
            if (reflectionChain.size() >= 3) {
                String finding = String.format(
                        "CRITICAL: Reflection chain detected in class '%s', method '%s'. This could be an obfuscated backdoor.",
                        cn.name.replace('/', '.'),
                        mn.name
                );
                findings.add(finding);
            }
        }
    }

    private boolean isReflectionCall(AbstractInsnNode insn) {
        if (insn.getType() == AbstractInsnNode.METHOD_INSN) {
            MethodInsnNode methodInsn = (MethodInsnNode) insn;
            String owner = methodInsn.owner;
            String name = methodInsn.name;
            return (owner.equals("java/lang/Class") && name.equals("forName")) ||
                   (owner.equals("java/lang/Class") && name.equals("getMethod")) ||
                   (owner.equals("java/lang/reflect/Method") && name.equals("invoke"));
        }
        return false;
    }

    private boolean isBase64(String s) {
        return s.length() > 20 && s.matches("^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$");
    }
    
    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private void analyzeBehavioralFingerprint(ClassNode cn, Set<String> findings) {
        int networkCallCount = 0;
        int fileIOCount = 0;
        int reflectionCallCount = 0;
        int cryptoOperationCount = 0;
        Set<String> externalDomains = new HashSet<>();
        StringBuilder allStrings = new StringBuilder();

        for (MethodNode mn : cn.methods) {
            for (AbstractInsnNode insn : mn.instructions) {
                if (insn.getType() == AbstractInsnNode.METHOD_INSN) {
                    MethodInsnNode methodInsn = (MethodInsnNode) insn;
                    String owner = methodInsn.owner;

                    if (NETWORK_CALL_PATTERNS.stream().anyMatch(owner::startsWith)) {
                        networkCallCount++;
                    }
                    if (owner.startsWith("java/io/")) {
                        fileIOCount++;
                    }
                    if (isReflectionCall(insn)) {
                        reflectionCallCount++;
                    }
                    if (CRYPTO_PATTERNS.contains(owner) || CRYPTO_PATTERNS.stream().anyMatch(methodInsn.name.toLowerCase()::contains)) {
                        cryptoOperationCount++;
                    }
                } else if (insn.getType() == AbstractInsnNode.LDC_INSN) {
                    LdcInsnNode ldc = (LdcInsnNode) insn;
                    if (ldc.cst instanceof String) {
                        String str = (String) ldc.cst;
                        allStrings.append(str);
                        extractDomains(str, externalDomains);
                    }
                }
            }
        }

        double stringEntropy = calculateShannonEntropy(allStrings.toString());

        BehaviorFingerprint fingerprint = new BehaviorFingerprint(
                networkCallCount,
                fileIOCount,
                reflectionCallCount,
                cryptoOperationCount,
                stringEntropy,
                externalDomains
        );

        if (fingerprint.isSuspicious()) {
            String finding = String.format(
                    "HIGH: Suspicious behavioral fingerprint detected in class '%s'. Details: [Network Calls: %d, File I/O: %d, Reflection: %d, Crypto: %d, String Entropy: %.2f, Domains: %s]",
                    cn.name.replace('/', '.'),
                    fingerprint.networkCallCount(),
                    fingerprint.fileIOCount(),
                    fingerprint.reflectionCallCount(),
                    fingerprint.cryptoOperationCount(),
                    fingerprint.stringEntropy(),
                    fingerprint.externalDomains().isEmpty() ? "None" : String.join(", ", fingerprint.externalDomains())
            );
            findings.add(finding);
        }
    }

    private void extractDomains(String text, Set<String> domains) {
        Matcher matcher = Pattern.compile("(?:https?://|www\\.)([^/\\s]+)").matcher(text);
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

    private void analyzeSymbolicExecution(ClassNode cn, Set<String> findings) {
        for (MethodNode mn : cn.methods) {
            if (mn.instructions == null || mn.instructions.size() == 0 || mn.instructions.size() > 500) {
                continue;
            }

            List<SymbolicExecutor.ExecutionPath> paths = symbolicExecutor.enumeratePaths(mn);
            for (SymbolicExecutor.ExecutionPath path : paths) {
                for (String note : path.notes) {
                    if (note.startsWith("Call: ")) {
                        String callSignature = note.substring("Call: ".length());
                        if (SUSPICIOUS_CALLS.containsKey(callSignature.replace('.', '/'))) {
                            String finding = String.format(
                                    "MEDIUM: Potentially dangerous call reachable via symbolic execution in class '%s', method '%s': %s. Reason: %s",
                                    cn.name.replace('/', '.'),
                                    mn.name,
                                    callSignature.replace('/', '.'),
                                    SUSPICIOUS_CALLS.get(callSignature.replace('.', '/'))
                            );
                            findings.add(finding);
                        }
                    }
                }
            }
        }
    }

}