package backdoordetected;

import com.microsoft.z3.BoolExpr;
import com.microsoft.z3.Context;
import com.microsoft.z3.IntExpr;
import org.jetbrains.java.decompiler.main.Fernflower;
import org.jetbrains.java.decompiler.main.decompiler.SingleFileSaver;
import org.jetbrains.java.decompiler.main.decompiler.DirectoryResultSaver;
import org.jetbrains.java.decompiler.main.extern.IFernflowerPreferences;
import org.jetbrains.java.decompiler.main.extern.IFernflowerLogger;
import org.jetbrains.java.decompiler.main.extern.IResultSaver;
import org.json.JSONObject;
import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.body.TypeDeclaration;
import org.objectweb.asm.ClassReader;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.zip.*;
import java.util.logging.Logger;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.lang.ProcessBuilder;
public class PluginWorker implements Runnable {
    private static final Logger logger = StandaloneLogger.getLogger();

    private final BlockingQueue<PrioritizedFile> queue;
    private final String currentApiKey;
    private final String currentModelName;
    private final String workerName;
    private final ScanMode scanMode;
    private final CountDownLatch latch;
    private final EventTriggerAnalyzer eventTriggerAnalyzer = new EventTriggerAnalyzer();
    private final BytecodeAnalyzer bytecodeAnalyzer = new BytecodeAnalyzer();
    private final SandboxAnalyzer sandboxAnalyzer = new SandboxAnalyzer();
    private final DataFlowAnalyzer dataFlowAnalyzer = new DataFlowAnalyzer();
    private final DependencyAnalyzer dependencyAnalyzer = new DependencyAnalyzer();
    private final DeobfuscationPipeline deobfuscationPipeline = new DeobfuscationPipeline();
    private final SymbolicAnalyzer symbolicAnalyzer = new SymbolicAnalyzer();

    private static final int MAX_PROMPT_LENGTH = 1_048_576;
    private static final long QUEUE_POLL_TIMEOUT_SECONDS = 5;

    public PluginWorker(BlockingQueue<PrioritizedFile> queue, String apiKey, String modelName,
                        String workerName, ScanMode mode, CountDownLatch latch) {
        this.queue = queue;
        this.currentApiKey = apiKey;
        this.currentModelName = modelName;
        this.workerName = workerName;
        this.scanMode = mode;
        this.latch = latch;

    }

    @Override
    public void run() {
        logger.info("[" + this.workerName + "] Worker STARTED for mode: " + scanMode.name());
        Path tempBaseDir = Paths.get("temp");

        try {
            Files.createDirectories(tempBaseDir);
            while (true) {
                PrioritizedFile pFile = null;
                try {
                    pFile = queue.poll(QUEUE_POLL_TIMEOUT_SECONDS, TimeUnit.SECONDS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    logger.warning("[" + this.workerName + "] Interrupted while polling queue.");
                    break;
                }
                if (pFile == null) {
                    logger.info("[" + this.workerName + "] No more tasks in queue (timeout). Exiting loop.");
                    break;
                }

                File plugin = pFile.file();
                logger.info("[" + this.workerName + "] Processing: " + plugin.getName());

                try {
                    switch (scanMode) {
                        case BYTECODE -> processBytecode(plugin.toPath(), tempBaseDir);
                        case SANDBOX -> processSandbox(plugin.toPath(), tempBaseDir);
                        case DATA_FLOW -> processDataFlow(plugin.toPath(), tempBaseDir);
                        case AI_MODERN, AI, AI_BACKDOOR_FOCUS -> processSequentialAi(plugin.toPath(), tempBaseDir);
                        case MODERN -> processModern(plugin.toPath(), tempBaseDir);
                        case DEPENDENCY -> processDependency(plugin.toPath());
                        case SYMBOLIC -> logger.warning("[" + this.workerName + "] SYMBOLIC mode is now integrated into DATA_FLOW. Please use DATA_FLOW mode instead.");
                        default -> logger.warning("[" + this.workerName + "] Unknown scan mode: " + scanMode);
                    }
                } catch (Exception e) {
                    logger.severe("[" + this.workerName + "] Error processing " + plugin.getName() + ": " + e.getMessage());
                    e.printStackTrace();
                }
            }
        } catch (IOException e) {
            logger.severe("[" + this.workerName + "] Fatal IO error: " + e.getMessage());
            e.printStackTrace();
        } finally {
            if (latch != null) latch.countDown();
            logger.info("[" + this.workerName + "] Worker FINISHED");
        }
    }

    private void processDependency(Path pluginPath) {
        try {
            dependencyAnalyzer.analyze(pluginPath);
        } catch (Exception e) {
            logger.severe(" DEPENDENCY error: " + e.getMessage());
        }
    }
    private void processSymbolic(Path pluginPath) {
        logger.warning("SYMBOLIC mode is deprecated and integrated into DATA_FLOW. Running data flow analysis instead.");
        processDataFlow(pluginPath, Paths.get("temp"));
    }
    private void processModern(Path pluginFile, Path tempBaseDir) {
        Path tmpDir = null;
        try {
            tmpDir = Files.createTempDirectory(tempBaseDir, pluginFile.getFileName().toString() + "_modern_");
            DecompilationResult res = performDecompilation(pluginFile, tmpDir, 0, true);
            List<Path> javaFiles = res.javaFiles();

            if (javaFiles.isEmpty()) {
                logger.warning(" No Java files after decompiling: " + pluginFile.getFileName());
                return;
            }

            logger.info("Analyzing " + javaFiles.size() + " files for event handlers...");
            EventTriggerAnalyzer.AnalysisResult result = eventTriggerAnalyzer.analyze(javaFiles);
            String formatted = formatEventFindings(result.findings());
            logger.info(formatted.isEmpty() ? "No suspicious patterns found" : formatted);
        } catch (IOException e) {
            logger.severe("MODERN error: " + e.getMessage());
        } finally {
            FileUtils.deleteDirectory(tmpDir);
        }
    }
    private void processSequentialAi(Path pluginPath, Path ignoredTempBaseDir) throws IOException {
        logger.info("[" + this.workerName + "] Starting AI-sequence for " + pluginPath.getFileName());
        DecompilationResult decomp = decompilePluginWithCache(pluginPath);

        List<Path> javaFiles = decomp.javaFiles();
        Path workingDir = decomp.workingDirectory();
        if (javaFiles.isEmpty()) {
            logger.warning("No Java files found after decompilation for: " + pluginPath.getFileName());
            return;
        }

        Map<Path, Path> javaToClassMap;
        try (Stream<Path> classStream = Files.walk(workingDir)) {
            javaToClassMap = buildJavaToClassMap(javaFiles, classStream.filter(p -> p.toString().endsWith(".class")).collect(Collectors.toList()));
        }

        Map<Path, List<String>> eventFindings;
        List<Path> failedFiles = new ArrayList<>();

        if (scanMode == ScanMode.AI_MODERN) {
            logger.info("Using DataFlowAnalyzer as pre-filter (AI_MODERN).");
            DataFlowAnalyzer.AnalysisResult dfRes = dataFlowAnalyzer.analyze(javaFiles, workingDir);
            eventFindings = new HashMap<>();
            dfRes.findings().forEach((fname, fnd) -> {
                javaFiles.stream()
                        .filter(p -> p.getFileName().toString().equals(fname))
                        .findFirst()
                        .ifPresent(p -> eventFindings.put(p, fnd));
            });
            failedFiles = dfRes.failedFiles();
        } else {
            EventTriggerAnalyzer.AnalysisResult evRes = eventTriggerAnalyzer.analyze(javaFiles);
            eventFindings = evRes.findings();
            failedFiles = evRes.failedFiles();
        }

        logger.info("Running parallel bytecode analysis on all class files...");
        List<Path> allClassFiles = new ArrayList<>(javaToClassMap.values());
        List<String> bcFindings = bytecodeAnalyzer.analyze(allClassFiles);
        if (!bcFindings.isEmpty()) {
            eventFindings.computeIfAbsent(Paths.get("BYTECODE_ANALYSIS"), k -> new ArrayList<>())
                    .addAll(bcFindings);
            
            logger.info("Bytecode analysis found " + bcFindings.size() + " potential issues:");
            bcFindings.forEach(finding -> logger.info("  -> " + finding));
        }

        if (!failedFiles.isEmpty()) {
            logger.warning("Syntax errors in " + failedFiles.size() + " files. Falling back to bytecode.");
            List<Path> classesToCheck = failedFiles.stream()
                    .map(javaToClassMap::get)
                    .filter(Objects::nonNull)
                    .collect(Collectors.toList());
            List<String> fallbackBcFindings = bytecodeAnalyzer.analyze(classesToCheck);
            if (!fallbackBcFindings.isEmpty()) {
                eventFindings.computeIfAbsent(Paths.get("BYTECODE_FALLBACK"), k -> new ArrayList<>())
                       .addAll(fallbackBcFindings);
            }
        }

        if (eventFindings.isEmpty()) {
            logger.info("No suspicious triggers found; skipping AI analyze.");
            return;
        }
        List<String> specialKeys = Arrays.asList("BYTECODE_ANALYSIS", "BYTECODE_FALLBACK");
        List<Path> suspiciousFiles = eventFindings.keySet().stream()
                .filter(p -> !specialKeys.contains(p.getFileName().toString()))
                .collect(Collectors.toList());

        Path pathToAnalyze = pluginPath;
        try {
            Path deobfuscatedJar = deobfuscationPipeline.deobfuscate(pluginPath);
            if (!deobfuscatedJar.equals(pluginPath)) {
                pathToAnalyze = deobfuscatedJar;
            }
        } catch (Exception e) {
            logger.warning("Deobfuscation failed: " + e.getMessage());
        }
        List<String> sanitizedNames = suspiciousFiles.stream()
                .map(p -> sanitizeForPrompt(p.getFileName().toString()))
                .collect(Collectors.toList());

        String directoryTree = generateDirectoryTree(workingDir);
        String fullModernResult = formatEventFindings(eventFindings);
        String codeToAnalyze = combineJavaFilesLimited(suspiciousFiles, MAX_PROMPT_LENGTH);
        logger.info("Sending " + suspiciousFiles.size() + " file(s) to AI for analysis:");
        for (Path file : suspiciousFiles) {
            Path relativePath = workingDir.relativize(file);
            logger.info("  -> File: " + file.getFileName() + " (Path: " + file.toAbsolutePath() + ")");
        }
        if (suspiciousFiles.isEmpty() && !eventFindings.isEmpty()) {
            logger.info("  -> No source files sent. AI will analyze based on bytecode findings and other metadata.");
        }
        logger.info("Analyzing plugin configuration files (e.g., config.yml)...");
        analyzePluginConfigs(workingDir, eventFindings);
        String prompt = buildUnifiedAiPrompt(sanitizedNames, fullModernResult, codeToAnalyze, directoryTree);
        String aiResult = sendToGemini(pluginPath.getFileName().toString(), prompt);
        logger.info("╔" + "═".repeat(80) + "╗");
        logger.info("║" + " ".repeat(34) + " AI ANALYSIS RESULT " + " ".repeat(28) + "║");
        logger.info("╠" + "═".repeat(80) + "╣");
        Arrays.stream(aiResult.split("\n")).forEach(line -> logger.info("║ " + line));
        logger.info("╚" + "═".repeat(80) + "╝");
    }
    private void processBytecode(Path pluginPath, Path tempBaseDir) {
        Path tmpDir = null;
        try {
            tmpDir = Files.createTempDirectory(tempBaseDir, pluginPath.getFileName().toString() + "_bytecode_");
            List<Path> classFiles = extractAllFiles(pluginPath, tmpDir);
            if (classFiles.isEmpty()) {
                logger.warning("No class files in " + pluginPath.getFileName());
                return;
            }
            List<String> findings = bytecodeAnalyzer.analyze(classFiles);
            if (findings.isEmpty()) {
                logger.info("No suspicious bytecode patterns found.");
            } else {
                logger.warning("Found " + findings.size() + " patterns.");
                findings.forEach(f -> logger.warning("  • " + f));
            }
        } catch (IOException e) {
            logger.severe("BYTECODE error: " + e.getMessage());
        } finally {
            FileUtils.deleteDirectory(tmpDir);
        }
    }

    private void processSandbox(Path pluginFile, Path tempBaseDir) {
        Path tmpDir = null;
        try { 
            tmpDir = Files.createTempDirectory(tempBaseDir, pluginFile.getFileName().toString() + "_sandbox_");
            DecompilationResult res = performDecompilation(pluginFile, tmpDir, 0, true);
            List<Path> javaFiles = res.javaFiles();
            if (javaFiles.isEmpty()) {
                logger.warning("No Java files found for sandbox analysis: " + pluginFile.getFileName());
                return;
            }
            Map<String, List<String>> findings = sandboxAnalyzer.analyze(javaFiles);
            if (findings.isEmpty()) {
                logger.info("No dangerous event handlers found.");
            } else {
                findings.forEach((ev, calls) -> {
                    logger.warning("Event: " + ev);
                    calls.forEach(c -> logger.warning("  • " + c));
                });
            }
        } catch (IOException e) {
            logger.severe("SANDBOX error: " + e.getMessage());
        } finally {
            FileUtils.deleteDirectory(tmpDir);
        }
    }

    private void processDataFlow(Path pluginFile, Path tempBaseDir) {
        Path tmpDir = null;
        try {
            tmpDir = Files.createTempDirectory(tempBaseDir, pluginFile.getFileName().toString() + "_dataflow_");
            DecompilationResult res = performDecompilation(pluginFile, tmpDir, 0, true);
            List<Path> javaFiles = res.javaFiles();
            if (javaFiles.isEmpty()) {
                logger.warning("No Java files found for dataflow analysis: " + pluginFile.getFileName());
                return;
            }
            DataFlowAnalyzer.AnalysisResult result = dataFlowAnalyzer.analyze(javaFiles, tmpDir);
            if (result.findings().isEmpty()) {
                logger.info("No dangerous dataflows detected.");
            } else {
                result.findings().forEach((f, flows) -> {
                    logger.warning("File: " + f);
                    flows.forEach(fl -> logger.warning("  • " + fl));
                });
            }
        } catch (IOException e) {
            logger.severe("DATA_FLOW error: " + e.getMessage());
        } finally {
            FileUtils.deleteDirectory(tmpDir);
        }
    }

    public record PrioritizedFile(File file, int depth) implements Comparable<PrioritizedFile> {
        @Override
        public int compareTo(PrioritizedFile o) {
            return Integer.compare(this.depth, o.depth);
        }
    }
    private String formatEventFindings(Map<Path, List<String>> findings) {
        if (findings == null || findings.isEmpty()) return "";
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<Path, List<String>> e : findings.entrySet()) {
            sb.append("File: ").append(e.getKey().getFileName()).append("\n");
            for (String f : e.getValue()) sb.append("  • ").append(f).append("\n");
        }
        return sb.toString();
    }
    private void analyzePluginConfigs(Path workingDir, Map<Path, List<String>> findings) {
        try (Stream<Path> files = Files.walk(workingDir)) {
            files.filter(p -> {
                String fileName = p.toString();
                return fileName.endsWith(".yml") || fileName.endsWith(".yaml");
            }).forEach(yamlFile -> {
                try {
                    String content = Files.readString(yamlFile, StandardCharsets.UTF_8);
                    analyzeYamlContent(yamlFile, content, findings);
                } catch (IOException e) {
                    logger.warning("Could not read YAML file: " + yamlFile.getFileName());
                }
            });
        } catch (IOException e) {
            logger.warning("Failed to scan YAML files: " + e.getMessage());
        }
    }

    private void analyzeYamlContent(Path yamlFile, String content, Map<Path, List<String>> findings) {
        Pattern cmdPattern = Pattern.compile("(?:command|execute|cmd):\\s*['\"]?([^'\"\\n]+)['\"]?");
                Matcher m = cmdPattern.matcher(content);
                while (m.find()) {
                    String cmd = m.group(1).trim();
                    if (cmd.toLowerCase().contains("op ") || cmd.toLowerCase().contains("execute")) {
                        findings.computeIfAbsent(yamlFile, k -> new ArrayList<>())
                                .add("MEDIUM: Dangerous command in " + yamlFile.getFileName() + ": " + cmd);
                    }
                }

        Pattern urlPattern = Pattern.compile("(https?://[^\\s\"']+)");
        Matcher urlMatcher = urlPattern.matcher(content);
        while (urlMatcher.find()) {
            String url = urlMatcher.group(1).toLowerCase();
            if (url.contains("pastebin") || url.contains("discord.com/api/webhooks")) {
                findings.computeIfAbsent(yamlFile, k -> new ArrayList<>())
                        .add("HIGH: Suspicious URL in " + yamlFile.getFileName() + ": " + url);
            }
        }

    }
    private DecompilationResult decompilePluginWithCache(Path pluginFile) throws IOException {
        Path cacheDir = Paths.get("decompile_cache");
        Files.createDirectories(cacheDir);
        String checksum;
        try {
            checksum = calculateFileChecksum(pluginFile);
        } catch (NoSuchAlgorithmException e) {
            throw new IOException("Checksum algorithm missing", e);
        }
        Path specificCache = cacheDir.resolve(pluginFile.getFileName().toString() + "_" + checksum);

        boolean needsExtraction = !Files.exists(specificCache) || !Files.isDirectory(specificCache) || isDirEmpty(specificCache);
        if (needsExtraction) {
            logger.info("Cache is empty or non-existent, extracting files from " + pluginFile.getFileName());
            extractAllFiles(pluginFile, specificCache);
        }
        if (!needsExtraction) {
            logger.info("Found valid cache. Reusing decompiled files from: " + specificCache.getFileName());
            List<Path> javaFiles;
            Path decompiledDir = specificCache.resolve("decompiled");
            Files.createDirectories(decompiledDir);
            try (Stream<Path> walk = Files.walk(decompiledDir)) {
                javaFiles = walk.filter(p -> p.toString().endsWith(".java")).collect(Collectors.toList());
            }
            if (!javaFiles.isEmpty()) {
                return new DecompilationResult(javaFiles, new HashMap<>(), specificCache);
            } else {
                logger.warning("Cache exists but contains no .java files. Re-running decompilation...");
            }
        }
        logger.info("No valid cache found. Starting fresh decompilation...");
        Path decompiledOutputDir = specificCache.resolve("decompiled");
        return performDecompilation(pluginFile, specificCache, 0, true);
    }

    private DecompilationResult performDecompilation(Path pluginFile, Path outputDir, int totalClassFiles, boolean collectClassCount) {
        try {
            logger.info("[DEBUG] Performing decompilation. Input: " + pluginFile.getFileName() + ", Output Dir: " + outputDir.getFileName());
            Path decompiledOutputDir = outputDir.resolve("decompiled");
            Files.createDirectories(decompiledOutputDir);

            Map<String, Object> options = new HashMap<>();
            options.put("dgs", "1");
            options.put("rsy", "1");
            options.put("ind", "    ");
            options.put("log", "warn");

            IFernflowerLogger vineLogger = new IFernflowerLogger() {
                @Override
                public void writeMessage(String message, Severity severity) {
                    if (severity.ordinal() >= Severity.WARN.ordinal()) {
                        logger.warning("[Vineflower] " + message);
                    }
                }

                @Override
                public void writeMessage(String message, Severity severity, Throwable t) {
                    logger.log(java.util.logging.Level.WARNING, "[Vineflower] " + message, t);
                }
            };

            Fernflower engine = new Fernflower(new DirectoryResultSaver(decompiledOutputDir.toFile()), options, vineLogger);
            engine.addSource(pluginFile.toFile());
            engine.decompileContext();

        } catch (IOException e) {
            logger.log(java.util.logging.Level.SEVERE, "Decompilation failed with IOException", e);
        } catch (OutOfMemoryError e) {
            logger.severe("CRITICAL: OutOfMemoryError during decompilation. The plugin might be too large or obfuscated.");
            throw e;
        } catch (Exception e) {
            logger.log(java.util.logging.Level.SEVERE, "An unexpected error occurred during decompilation", e);
        }

        Path decompiledDir = outputDir.resolve("decompiled");
        List<Path> javaFiles;
        try (Stream<Path> walk = Files.walk(decompiledDir)) {
            javaFiles = walk.filter(p -> p.toString().endsWith(".java")).collect(Collectors.toList());
        } catch (IOException e) {
            javaFiles = new ArrayList<>();
            logger.log(java.util.logging.Level.SEVERE, "Failed to collect .java files after decompilation", e);
        }

        if (javaFiles.isEmpty()) {
            logger.info("Vineflower failed, attempting decompilation with Krakatau...");
            try {
                Path krakatauOutputDir = outputDir.resolve("krakatau_decompiled");
                Files.createDirectories(krakatauOutputDir);
                ProcessBuilder pb = new ProcessBuilder(
                        "python",
                        "resource/krakatau/decompile.py",
                        pluginFile.toAbsolutePath().toString(),
                        "-out",
                        krakatauOutputDir.toAbsolutePath().toString(),
                        "-skip"
                );
                pb.redirectErrorStream(true);  
                Process process = pb.start();
                int exitCode = process.waitFor();

                if (exitCode != 0) {
                    logger.severe("Krakatau decompilation failed with exit code: " + exitCode);
                } else {
                    logger.info("Krakatau decompilation finished. Collecting files...");
                    try (Stream<Path> walk = Files.walk(krakatauOutputDir)) {
                        javaFiles = walk.filter(p -> p.toString().endsWith(".java")).collect(Collectors.toList());
                        logger.info("Collected " + javaFiles.size() + " java files from Krakatau.");
                    }
                }
            } catch (IOException | InterruptedException e) {
                logger.log(java.util.logging.Level.SEVERE, "Krakatau execution failed", e);
            }
        }

        return new DecompilationResult(javaFiles, new HashMap<>(), outputDir);
    }

    private boolean isDirEmpty(final Path directory) throws IOException {
        if (!Files.isDirectory(directory)) {
            return false;
        }
        try (DirectoryStream<Path> dirStream = Files.newDirectoryStream(directory)) {
            return !dirStream.iterator().hasNext();
        }
    }


    private List<Path> extractAllFiles(Path pluginFile, Path outputDir) throws IOException {
        List<Path> classFiles = new ArrayList<>();
        try (ZipInputStream zis = new ZipInputStream(Files.newInputStream(pluginFile))) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                if (!entry.isDirectory()) {
                    Path out = outputDir.resolve(entry.getName());
                    Files.createDirectories(out.getParent());
                    Files.copy(zis, out, StandardCopyOption.REPLACE_EXISTING);
                    if (entry.getName().endsWith(".class")) {
                        classFiles.add(out);
                    }
                }
            }
        }
        return classFiles;
    }

    private Map<Path, Path> buildJavaToClassMap(List<Path> javaFiles, List<Path> classFiles) {
        logger.info("[DEBUG] Building reliable Java-to-Class map using FQN...");
        Map<String, Path> fqnToClass = new HashMap<>();
        for (Path c : classFiles) {
            try (InputStream is = Files.newInputStream(c)) {
                ClassReader cr = new ClassReader(is);
                String fqn = cr.getClassName().replace('/', '.');
                fqnToClass.put(fqn, c);
            } catch (IOException | IllegalArgumentException ex) {
            }
        }

        Map<Path, Path> finalMap = new HashMap<>();
        for (Path j : javaFiles) {
            try {
                StaticJavaParser.parse(j).getPrimaryType().ifPresent(type -> {
                    type.getFullyQualifiedName().ifPresent(fqn -> {
                        if (fqnToClass.containsKey(fqn)) {
                            finalMap.put(j, fqnToClass.get(fqn));
                        }
                    });
                });
            } catch (Exception e) {
                logger.fine("Could not parse java file: " + j.getFileName());
            }
        }
        logger.info("[DEBUG] Mapped " + fqnToClass.size() + " FQNs from .class files.");
        logger.info("[DEBUG] Successfully created " + finalMap.size() + " Java-to-Class mappings.");
        return finalMap;
    }
    private String buildUnifiedAiPrompt(List<String> suspiciousFileNames, String findings, String code, String directoryTree) {
        String fileList = suspiciousFileNames.isEmpty() ? "N/A" : String.join(", ", suspiciousFileNames);
        return String.format("""
             You are a world-class Minecraft plugin security expert. Your **only mission** is to determine if this plugin contains a **hidden, malicious backdoor**. You must be extremely precise and avoid false positives.
 
             **CRITICAL INSTRUCTIONS:**
             1.  **PRIMARY GOAL: FIND TRUE BACKDOORS.** A true backdoor is **deceptive and hidden**. Prioritize finding these:
                 *   Is triggered by a **secret, non-obvious action** (e.g., a specific chat message, a hardcoded player name/UUID, joining at a specific time).
                 *   Communicates with **suspicious, hardcoded external servers** (e.g., pastebin, discord webhooks, random IPs) to fetch commands or exfiltrate data.
                 *   Uses **heavy obfuscation** (e.g., decoding strings from Base64/Hex/byte arrays) specifically to hide malicious keywords like `setOp`, `exec`, or `dispatchCommand`.

             2.  **SECONDARY GOAL: IDENTIFY CONFIGURABLE FEATURES THAT CAN BE ABUSED.** These are **NOT backdoors**, but are worth noting.
                 *   A feature is **NOT a backdoor** if it requires a server administrator to edit a file (`.yml`, `.json`, etc.) in the plugin's folder.
                 *   **Example:** A plugin that runs commands from `commands.yml` is a feature. It is the admin's responsibility to secure that file. Report this as a "Configuration Vulnerability", not a backdoor.
                 *   **Example:** A plugin that grants OP status based on a value in a data file (like AuthMe's Limbo feature) is a feature. Report this as a "Configuration Vulnerability".
                 *   **Example:** A plugin using `Runtime.exec` for a legitimate purpose like database backups (`mysqldump`) is a feature. Do not flag this unless the command arguments can be controlled by a non-admin.

             3.  **IGNORE LIBRARY FINDINGS:** The `INITIAL FINDINGS` may contain suspicious calls (like reflection or unreachable code) from bundled libraries (e.g., `io.netty`, `com.zaxxer.hikari`, `org.mariadb`, `com.mysql`, `javax.mail`). These are almost always **FALSE POSITIVES**. Ignore them unless there is direct evidence they are being used maliciously by the plugin's own code.
 
             ### SOURCE CODE & CONTEXT
             %s
             Directory Tree: %s
             SUSPICIOUS FILES: %s
             INITIAL FINDINGS:
             %s
 
             ### YOUR TASK & RESPONSE FORMAT
             Based on the criteria above, analyze the plugin.
             **Strictly follow this format.**

             **Malicious:** [YES/NO] (Only YES if you find a **true backdoor** as defined in rule #1)
             **Confidence:** [0-100%%]
             **Severity:** [CRITICAL / HIGH / MEDIUM / LOW / NONE]
             **Vulnerability Type:** [Hardcoded Backdoor / Command Injection / Remote Code Execution / Malicious Download / Obfuscation / Data Stealing / Configuration Vulnerability / False Positive]

             ### BRIEF REASONING
             Provide a concise explanation. If you found a true backdoor, explain it first. If you only found configurable features that can be abused (rule #2), explain that clearly and state that it's not a true backdoor but a configuration risk.
             """, code, directoryTree, fileList, findings);
     }

    private String sendToGemini(String pluginName, String content) {
        if (currentApiKey == null || currentApiKey.isEmpty() || currentApiKey.startsWith("YOUR_")) {
            return "⚠️ AI analysis skipped: API key not configured";
        }

        int maxRetries = 3;
        int retryCount = 0;
        while (retryCount < maxRetries) {
            HttpURLConnection conn = null;
            try {
                String urlString = "https://generativelanguage.googleapis.com/v1beta/models/"
                        + currentModelName + ":generateContent?key=" + currentApiKey;
                URL url = new URL(urlString);
                conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("POST");
                conn.setRequestProperty("Content-Type", "application/json; charset=utf-8");
                conn.setConnectTimeout(15_000);
                conn.setReadTimeout(60_000);
                conn.setDoOutput(true);

                String safeContent = escapeJson(content);
                String json = "{\"contents\": [{\"parts\": [{\"text\": \"" + safeContent + "\"}]}]}";

                try (OutputStream os = conn.getOutputStream()) {
                    os.write(json.getBytes(StandardCharsets.UTF_8));
                }

                int code = conn.getResponseCode();
                InputStream is = (code >= 200 && code < 300) ? conn.getInputStream() : conn.getErrorStream();
                String responseStr = "";
                if (is != null) {
                    try (BufferedReader br = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
                        responseStr = br.lines().collect(Collectors.joining());
                    }
                }

                if (code == HttpURLConnection.HTTP_OK) {
                    JSONObject jr = new JSONObject(responseStr);
                    if (!jr.has("candidates") || jr.getJSONArray("candidates").isEmpty()) {
                        String blockReason = jr.has("promptFeedback") ? jr.getJSONObject("promptFeedback").optString("blockReason", "Unknown") : "No candidates found";
                        return "AI analysis failed: Prompt was blocked or returned no candidates. Reason: " + blockReason;
                    }
                    JSONObject candidate = jr.getJSONArray("candidates").getJSONObject(0);
                    if (!candidate.has("content")) {
                        return "AI analysis failed: Candidate is missing 'content'. Finish reason: " + candidate.optString("finishReason", "Unknown");
                    }
                    JSONObject contentObj = candidate.getJSONObject("content");
                    if (!contentObj.has("parts") || contentObj.getJSONArray("parts").isEmpty()) {
                        return "AI analysis failed: Content is missing 'parts'. This might indicate a blocked prompt or an empty response.";
                    }
                    return contentObj.getJSONArray("parts").getJSONObject(0).getString("text");
                } else if (code == 429) {
                    logger.warning("Rate limited. Retrying... (" + (retryCount + 1) + "/" + maxRetries + ")");
                    Thread.sleep(5000L * (retryCount + 1));
                    retryCount++;
                } else if (code == 503) {
                    logger.warning("AI service unavailable (503). Retrying... (" + (retryCount + 1) + "/" + maxRetries + ")");
                    Thread.sleep(10000L * (retryCount + 1));
                    retryCount++;
                } else {
                    return "AI failed (HTTP " + code + "): " + responseStr;
                }
            } catch (IOException e) {
                logger.warning("AI connection error: " + e.getMessage() + ". Retrying...");
                retryCount++;
                try {
                    Thread.sleep(3000L * retryCount);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    return "AI analysis interrupted";
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return "AI analysis interrupted during backoff";
            }
            finally {
                if (conn != null) conn.disconnect();
            }
        }
        return "AI analysis failed after " + maxRetries + " retries";
    }

    private String escapeJson(String text) {
        if (text == null) return "";
        return text.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    private String sanitizeForPrompt(String input) {
        if (input == null) return "";
        return input.replaceAll("[^a-zA-Z0-9._-]", "_")
                    .substring(0, Math.min(input.length(), 100));
    }

    private String calculateFileChecksum(Path filePath) throws IOException, NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (InputStream fis = Files.newInputStream(filePath)) {
            byte[] buf = new byte[8192];
            int r;
            while ((r = fis.read(buf)) != -1) {
                digest.update(buf, 0, r);
            }
        }
        byte[] h = digest.digest();
        StringBuilder sb = new StringBuilder();
        for (byte b : h) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    private String combineJavaFilesLimited(List<Path> javaFiles, int maxLen) throws IOException {
        StringBuilder sb = new StringBuilder();
        for (Path p : javaFiles) {
            String content = Files.readString(p, StandardCharsets.UTF_8);
            String header = "=== File: " + p.getFileName() + " ===\n```java\n";
            String footer = "\n```\n\n";
            int projectedLength = sb.length() + header.length() + content.length() + footer.length();

            if (projectedLength > maxLen) {
                int availableSpace = maxLen - sb.length() - header.length() - footer.length() - 50;
                if (availableSpace <= 0) {
                    sb.append("\n... (more files exist but could not be included due to size limits)");
                    break;
                }
                sb.append(header);
                sb.append(content, 0, Math.min(content.length(), availableSpace));
                sb.append("\n... (file truncated)\n").append(footer);
                break;
            }
            sb.append(header).append(content).append(footer);
        }
        return sb.toString();
    }

    private String generateDirectoryTree(Path rootDir) {
        if (rootDir == null || !Files.isDirectory(rootDir)) {
            return "Could not generate directory tree: root is not a valid directory.\n";
        }
        StringBuilder sb = new StringBuilder();
        sb.append(rootDir.getFileName().toString()).append("\n");
        try (Stream<Path> stream = Files.walk(rootDir)) {
            List<Path> paths = stream.filter(p -> !p.equals(rootDir)).sorted().collect(Collectors.toList());
            for (Path path : paths) {
                int depth = rootDir.relativize(path).getNameCount();
                sb.append("│   ".repeat(Math.max(0, depth - 1)));
                sb.append("├── ").append(path.getFileName()).append("\n");
            }
        } catch (IOException e) {
            return "Error generating directory tree: " + e.getMessage() + "\n";
        }
        int maxTreeLength = 30000;
        if (sb.length() > maxTreeLength) {
            sb.setLength(maxTreeLength);
            sb.append("\n... (directory tree truncated due to size)\n");
        }
        return sb.toString();
    }

    public record DecompilationResult(List<Path> javaFiles, Map<Path, Path> javaToClassMap, Path workingDirectory) {}
}
