package backdoordetected.services;

import backdoordetected.analyzers.*;
import backdoordetected.decompiler.DecompilerManager;
import backdoordetected.detection.LMXBackdoorDetector;
import backdoordetected.exceptions.AnalysisException;
import backdoordetected.models.ComprehensiveAnalysisResult;
import backdoordetected.models.DecompilationResult;
import backdoordetected.utils.FileUtils;
import backdoordetected.utils.ScanMode;
import backdoordetected.utils.StandaloneLogger;
import com.github.javaparser.StaticJavaParser;
import org.objectweb.asm.ClassReader;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.logging.Logger;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class AnalysisCoordinator {
    private static final Logger logger = StandaloneLogger.getLogger();
    private static final int MAX_PROMPT_LENGTH = 100_000;

    private final EventTriggerAnalyzer eventTriggerAnalyzer = new EventTriggerAnalyzer();
    private final BytecodeAnalyzer bytecodeAnalyzer = new BytecodeAnalyzer();
    private final DataFlowAnalyzer dataFlowAnalyzer = new DataFlowAnalyzer();
    private final DecompilerManager decompilerManager = new DecompilerManager();
    private final CacheService cacheService;

    public AnalysisCoordinator(CacheService cacheService) {
        this.cacheService = cacheService;
    }

    public AnalysisCoordinator() {
        this(new CacheService());
    }

    public ComprehensiveAnalysisResult analyze(Path pluginPath, ScanMode scanMode, String workerName)
            throws AnalysisException {
        try {
            logger.info("[" + workerName + "] Scanning for known backdoor signatures...");
            LMXBackdoorDetector.BackdoorScanResult backdoorScan = LMXBackdoorDetector.analyze(pluginPath);

            if (backdoorScan.hasAnyBackdoor()) {
                logger.warning("═══════════════════════════════════════════════════════");
                logger.warning("CRITICAL: KNOWN BACKDOOR SIGNATURE DETECTED!");
                if (backdoorScan.hasLMXBackdoor) {
                    logger.warning("  → L.M.X backdoor pattern found");
                }
                if (backdoorScan.hasOpenEctasy) {
                    logger.warning("  → OpenEctasy malware pattern found");
                }
                logger.warning("═══════════════════════════════════════════════════════");
            }

            logger.info("[" + workerName + "] Decompiling plugin...");
            DecompilationResult decomp = decompilePluginWithCache(pluginPath);

            List<Path> javaFiles = decomp.javaFiles();
            Path workingDir = decomp.workingDirectory();

            if (javaFiles.isEmpty()) {
                logger.warning("No Java files found after decompilation");
                return new ComprehensiveAnalysisResult(
                        Map.of(), List.of(), backdoorScan, false, "", List.of(), "");
            }

            Map<Path, Path> javaToClassMap;
            try {
                Path classFilesDir = workingDir.resolve("extracted_classes");
                Files.createDirectories(classFilesDir);

                List<Path> classFiles = new ArrayList<>();
                try (java.util.jar.JarFile jarFile = new java.util.jar.JarFile(pluginPath.toFile())) {
                    java.util.Enumeration<java.util.jar.JarEntry> entries = jarFile.entries();
                    while (entries.hasMoreElements()) {
                        java.util.jar.JarEntry entry = entries.nextElement();
                        if (!entry.isDirectory() && entry.getName().endsWith(".class")) {
                            Path classFile = classFilesDir.resolve(entry.getName());
                            Files.createDirectories(classFile.getParent());
                            try (InputStream is = jarFile.getInputStream(entry)) {
                                Files.copy(is, classFile, StandardCopyOption.REPLACE_EXISTING);
                                classFiles.add(classFile);
                            }
                        }
                    }
                }

                logger.info("Extracted " + classFiles.size() + " class files from JAR");
                javaToClassMap = buildJavaToClassMap(javaFiles, classFiles);
                logger.info("Mapped " + javaToClassMap.size() + " Java files to class files");
            } catch (IOException e) {
                logger.warning("Failed to extract class files: " + e.getMessage());
                javaToClassMap = Map.of();
            }
            Map<Path, List<String>> eventFindings;
            List<Path> failedFiles;

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

            logger.info("Running bytecode analysis...");
            List<Path> allClassFiles = new ArrayList<>(javaToClassMap.values());
            logger.info("Analyzing " + allClassFiles.size() + " class files...");
            List<String> bcFindings = bytecodeAnalyzer.analyze(allClassFiles);
            logger.info("Bytecode analysis complete. Findings: " + bcFindings.size());

            if (!bcFindings.isEmpty()) {
                logger.info("Bytecode findings details:");
                for (String finding : bcFindings) {
                    logger.info("  - " + finding);
                }
                eventFindings.computeIfAbsent(Paths.get("BYTECODE_ANALYSIS"), k -> new ArrayList<>())
                        .addAll(bcFindings);
            } else {
                logger.info("No bytecode findings detected.");
            }

            boolean lmxStringLiteralFound = findLmxStringLiteral(javaFiles, "L/M/X");
            if (lmxStringLiteralFound) {
                eventFindings.computeIfAbsent(Paths.get("LMX_STRING_LITERAL"), k -> new ArrayList<>())
                        .add("CRITICAL: L.M.X backdoor pattern found as string literal in decompiled code.");
            }

            if (backdoorScan.hasAnyBackdoor()) {
                eventFindings.computeIfAbsent(Paths.get("KNOWN_BACKDOOR_SIGNATURES"), k -> new ArrayList<>())
                        .addAll(backdoorScan.findings);
            }
            analyzePluginConfigs(workingDir, eventFindings);
            List<String> specialKeys = Arrays.asList("BYTECODE_ANALYSIS", "BYTECODE_FALLBACK",
                    "LMX_STRING_LITERAL", "KNOWN_BACKDOOR_SIGNATURES");
            List<Path> suspiciousFiles = eventFindings.keySet().stream()
                    .filter(p -> !specialKeys.contains(p.getFileName().toString()))
                    .collect(Collectors.toList());

            String directoryTree = generateDirectoryTree(workingDir);
            String combinedCode = combineJavaFilesLimited(suspiciousFiles, MAX_PROMPT_LENGTH);

            cacheService.logCacheStats();

            return new ComprehensiveAnalysisResult(
                    eventFindings,
                    failedFiles,
                    backdoorScan,
                    lmxStringLiteralFound,
                    directoryTree,
                    suspiciousFiles,
                    combinedCode);

        } catch (IOException e) {
            logger.severe("[" + workerName + "] Analysis failed with IOException: " + e.getMessage());
            e.printStackTrace();
            throw new AnalysisException("Analysis failed", e);
        } catch (Exception e) {
            logger.severe("[" + workerName + "] Analysis failed with unexpected exception: " + e.getMessage());
            e.printStackTrace();
            throw new AnalysisException("Analysis failed: " + e.getMessage(), e);
        }
    }

    private DecompilationResult decompilePluginWithCache(Path pluginFile) throws IOException {
        String checksum;
        try {
            checksum = calculateFileChecksum(pluginFile);
        } catch (NoSuchAlgorithmException e) {
            throw new IOException("Checksum algorithm missing", e);
        }
        var cachedResult = cacheService.getDecompilation(checksum);
        if (cachedResult.isPresent()) {
            logger.info("Cache HIT! Reusing decompilation from memory cache for: " + pluginFile.getFileName());
            return cachedResult.get();
        }

        Path cacheDir = Paths.get("decompile_cache");
        Files.createDirectories(cacheDir);
        Path specificCache = cacheDir.resolve(pluginFile.getFileName().toString() + "_" + checksum);

        boolean needsExtraction = !Files.exists(specificCache) || !Files.isDirectory(specificCache)
                || isDirEmpty(specificCache);

        if (!needsExtraction) {
            logger.info("Disk cache HIT! Reusing decompiled files from: " + specificCache.getFileName());
            Path decompiledDir = specificCache.resolve("decompiled");
            Files.createDirectories(decompiledDir);

            try (Stream<Path> walk = Files.walk(decompiledDir)) {
                List<Path> javaFiles = walk.filter(p -> p.toString().endsWith(".java"))
                        .collect(Collectors.toList());
                if (!javaFiles.isEmpty()) {
                    DecompilationResult result = new DecompilationResult(javaFiles, new HashMap<>(), specificCache);
                    cacheService.putDecompilation(checksum, result);
                    return result;
                }
            }
        }

        logger.info("Cache MISS. Starting fresh decompilation...");
        Files.createDirectories(specificCache);
        DecompilationResult result = decompilerManager.decompile(pluginFile, specificCache);
        cacheService.putDecompilation(checksum, result);
        logger.info("Decompilation result cached in memory for future use");

        return result;
    }

    private boolean isDirEmpty(Path directory) throws IOException {
        if (!Files.isDirectory(directory))
            return false;
        try (DirectoryStream<Path> dirStream = Files.newDirectoryStream(directory)) {
            return !dirStream.iterator().hasNext();
        }
    }

    private String calculateFileChecksum(Path filePath) throws IOException, NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (InputStream fis = Files.newInputStream(filePath)) {
            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                digest.update(buffer, 0, bytesRead);
            }
        }
        byte[] hashBytes = digest.digest();
        StringBuilder sb = new StringBuilder();
        for (byte b : hashBytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private Map<Path, Path> buildJavaToClassMap(List<Path> javaFiles, List<Path> classFiles) {
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
            }
        }
        return finalMap;
    }

    private boolean findLmxStringLiteral(List<Path> javaFiles, String pattern) throws IOException {
        Pattern lmxPattern = Pattern.compile(Pattern.quote(pattern), Pattern.CASE_INSENSITIVE);
        for (Path javaFile : javaFiles) {
            String content = Files.readString(javaFile, StandardCharsets.UTF_8);
            if (lmxPattern.matcher(content).find()) {
                logger.warning("L.M.X string literal '" + pattern + "' found in " + javaFile.getFileName());
                return true;
            }
        }
        return false;
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
                }
            });
        } catch (IOException e) {
            logger.warning("Failed to scan YAML files: " + e.getMessage());
        }
    }

    private void analyzeYamlContent(Path yamlFile, String content, Map<Path, List<String>> findings) {
        Pattern cmdPattern = Pattern.compile("(?:command|execute|cmd):\\s*['\"]?([^'\"\\n]+)['\"]?");
        var m = cmdPattern.matcher(content);
        while (m.find()) {
            String cmd = m.group(1).trim();
            if (cmd.toLowerCase().contains("op ") || cmd.toLowerCase().contains("execute")) {
                findings.computeIfAbsent(yamlFile, k -> new ArrayList<>())
                        .add("MEDIUM: Dangerous command in " + yamlFile.getFileName() + ": " + cmd);
            }
        }
    }

    private String generateDirectoryTree(Path rootDir) {
        StringBuilder tree = new StringBuilder();
        try (Stream<Path> paths = Files.walk(rootDir, 3)) {
            paths.filter(Files::isDirectory)
                    .limit(50)
                    .forEach(p -> {
                        int depth = rootDir.relativize(p).getNameCount();
                        tree.append("  ".repeat(depth)).append("└─ ")
                                .append(p.getFileName()).append("/\n");
                    });
        } catch (IOException e) {
            tree.append("(Unable to generate tree)");
        }
        return tree.toString();
    }

    private String combineJavaFilesLimited(List<Path> javaFiles, int maxLen) {
        StringBuilder combined = new StringBuilder();
        int currentLen = 0;

        for (Path javaFile : javaFiles) {
            if (currentLen >= maxLen)
                break;

            if (!Files.exists(javaFile)) {
                continue;
            }

            try {
                int remaining = maxLen - currentLen;
                String content = readFileWithLimit(javaFile, remaining);

                combined.append("// File: ").append(javaFile.getFileName()).append("\n");
                combined.append(content).append("\n\n");
                currentLen += content.length();
            } catch (IOException e) {
                logger.warning("Could not read file: " + javaFile);
            }
        }

        return combined.toString();
    }

    private String readFileWithLimit(Path file, int maxChars) throws IOException {
        StringBuilder content = new StringBuilder();
        int charsRead = 0;

        try (Stream<String> lines = Files.lines(file, StandardCharsets.UTF_8)) {
            Iterator<String> iterator = lines.iterator();
            while (iterator.hasNext() && charsRead < maxChars) {
                String line = iterator.next();
                int remaining = maxChars - charsRead;

                if (line.length() > remaining) {
                    content.append(line, 0, remaining);
                    charsRead += remaining;
                    break;
                } else {
                    content.append(line).append("\n");
                    charsRead += line.length() + 1;
                }
            }
        }

        return content.toString();
    }
}
