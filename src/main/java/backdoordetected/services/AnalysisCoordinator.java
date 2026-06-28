package backdoordetected.services;

import backdoordetected.analyzers.*;
import backdoordetected.decompiler.DecompilerManager;
import backdoordetected.detection.LMXBackdoorDetector;
import backdoordetected.detection.SootTaintAnalyzer;
import backdoordetected.exceptions.AnalysisException;
import backdoordetected.models.BytecodeAnalysisResult;
import backdoordetected.models.ComprehensiveAnalysisResult;
import backdoordetected.models.DecompilationResult;
import backdoordetected.models.EventTriggerAnalysisResult;
import backdoordetected.models.ObfuscationResult;
import backdoordetected.models.SootAnalysisResult;
import backdoordetected.utils.ScanMode;
import backdoordetected.utils.StandaloneLogger;
import backdoordetected.utils.SafeJavaParser;
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
import org.objectweb.asm.ClassReader;

public class AnalysisCoordinator {
  private static final Logger logger = StandaloneLogger.getLogger();
  private static final int MAX_PROMPT_LENGTH = 100_000;

  private final DecompilerManager decompilerManager = new DecompilerManager();
  private final CacheService cacheService;
  private final ServiceLoader<PluginAnalyzer> analyzerLoader = ServiceLoader.load(PluginAnalyzer.class);

  private final DataFlowAnalyzer dataFlowAnalyzer = new DataFlowAnalyzer();
  private final EventTriggerAnalyzer eventTriggerAnalyzer = new EventTriggerAnalyzer();
  private final BytecodeAnalyzer bytecodeAnalyzer = new BytecodeAnalyzer();
  private final SootTaintAnalyzer sootTaintAnalyzer = new SootTaintAnalyzer();
  private final ObfuscationAnalyzer obfuscationAnalyzer = new ObfuscationAnalyzer();

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

      ObfuscationResult obfuscationResult = ObfuscationResult.empty("ObfuscationAnalyzer");

      if (javaFiles.isEmpty()) {
        logger.warning("No Java files found after decompilation");
        return new ComprehensiveAnalysisResult(
            Map.of(),
            List.of(),
            backdoorScan,
            "",
            List.of(),
            "",
            Map.of());
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
      List<String> bcFindings;

      ConfigService config = ConfigService.getInstance();
      boolean enableParallel = config.getBooleanProperty("enable_analyzer_parallel", false);

      int availableCores = Runtime.getRuntime().availableProcessors();
      if (enableParallel && availableCores <= 2) {
        logger.warning(
            "Analyzer-level parallelization disabled: CPU has only "
                + availableCores
                + " core(s). Parallel execution requires at least 3 cores for performance benefit.");
        logger.warning("Falling back to sequential mode to avoid context switching overhead.");
        enableParallel = false;
      }

      if (enableParallel) {
        logger.info("Analyzer-level parallelization ENABLED (CPU cores: " + availableCores + ")");
        int numThreads = config.getIntProperty("analyzer_parallel_threads", 3);

        ParallelAnalysisCoordinator parallelCoordinator = new ParallelAnalysisCoordinator(numThreads);
        try {
          ParallelAnalysisCoordinator.ParallelAnalysisResult parallelResult = parallelCoordinator.analyzeParallel(
              javaFiles,
              new ArrayList<>(javaToClassMap.values()),
              workingDir,
              scanMode == ScanMode.AI_MODERN);

          eventFindings = new HashMap<>(parallelResult.getEventFindings());
          failedFiles = parallelResult.getFailedFiles();
          bcFindings = parallelResult.getBytecodeFindings();
          logger.info("Bytecode analysis complete. Findings: " + bcFindings.size());
        } finally {
          parallelCoordinator.shutdown();
        }
      } else {
        EventTriggerAnalysisResult evRes = (EventTriggerAnalysisResult) eventTriggerAnalyzer.analyze(
            pluginPath,
            javaFiles,
            new ArrayList<>(javaToClassMap.values()),
            workingDir,
            scanMode,
            workerName);
        eventFindings = evRes.getFileFindings();
        failedFiles = evRes.getFailedFiles();

        logger.info("Running bytecode analysis...");
        List<Path> allClassFiles = new ArrayList<>(javaToClassMap.values());
        logger.info("Analyzing " + allClassFiles.size() + " class files...");
        BytecodeAnalysisResult bcRes = (BytecodeAnalysisResult) bytecodeAnalyzer.analyze(
            pluginPath, javaFiles, allClassFiles, workingDir, scanMode, workerName);
        bcFindings = bcRes.getRawFindings();
        logger.info("Bytecode analysis complete. Findings: " + bcFindings.size());

        if (!bcFindings.isEmpty()) {
          logger.info("Bytecode findings details:");
          for (String finding : bcFindings) {
            logger.info("  - " + finding);
          }
          eventFindings
              .computeIfAbsent(Paths.get("BYTECODE_ANALYSIS"), k -> new ArrayList<>())
              .addAll(bcFindings);
        }
      }

      if (backdoorScan.hasAnyBackdoor()) {
        eventFindings
            .computeIfAbsent(Paths.get("KNOWN_BACKDOOR_SIGNATURES"), k -> new ArrayList<>())
            .addAll(backdoorScan.findings);
      }
      analyzePluginConfigs(workingDir, eventFindings);
      List<String> specialKeys = Arrays.asList(
          "BYTECODE_ANALYSIS",
          "BYTECODE_FALLBACK",
          "KNOWN_BACKDOOR_SIGNATURES");
      List<Path> suspiciousFiles = eventFindings.keySet().stream()
          .filter(
              p -> !specialKeys.contains(p.getFileName().toString())
                  && !eventFindings.get(p).isEmpty())
          .collect(Collectors.toList());

      logger.info("─────────────────────────────────────────────────────");
      logger.info("Analysis Summary:");
      logger.info("  Total findings: " + eventFindings.size() + " file/category(ies)");
      logger.info("  Suspicious files (after filtering): " + suspiciousFiles.size());
      if (!suspiciousFiles.isEmpty()) {
        logger.info("  Suspicious file list:");
        for (Path file : suspiciousFiles) {
          int findingCount = eventFindings.getOrDefault(file, List.of()).size();
          logger.info("    • " + file.getFileName() + " (" + findingCount + " finding(s))");
        }
      }
      logger.info("─────────────────────────────────────────────────────");

      logger.info("[" + workerName + "] Running Soot taint analysis...");
      SootAnalysisResult sootResult = (SootAnalysisResult) sootTaintAnalyzer.analyze(
          pluginPath,
          javaFiles,
          new ArrayList<>(javaToClassMap.values()),
          workingDir,
          scanMode,
          workerName);
      if (sootResult.hasFindings()) {
        logger.info("[Soot] Found " + sootResult.taintFlows().size() + " taint flow(s)");
        eventFindings
            .computeIfAbsent(Paths.get("SOOT_ANALYSIS"), k -> new ArrayList<>())
            .addAll(sootResult.findings());
      }

      String directoryTree = generateDirectoryTree(workingDir);
      String combinedCode = combineJavaFilesLimited(suspiciousFiles, MAX_PROMPT_LENGTH);

      logger.info("[" + workerName + "] Running Obfuscation Analysis...");
      obfuscationResult = (ObfuscationResult) obfuscationAnalyzer.analyze(
          pluginPath,
          javaFiles,
          new ArrayList<>(javaToClassMap.values()),
          workingDir,
          scanMode,
          workerName);
      if (obfuscationResult.isHeavilyObfuscated()) {
        logger.warning("HEAVY OBFUSCATION DETECTED! Score: " + obfuscationResult.score());
        for (String warning : obfuscationResult.warnings()) {
          logger.warning("  -> " + warning);
        }
      }

      cacheService.logCacheStats();

      Map<String, backdoordetected.models.PluginAnalysisResult> allPluginResults = new HashMap<>();
      allPluginResults.put("sootTaintAnalyzer", sootResult);
      allPluginResults.put("obfuscationAnalyzer", obfuscationResult);

      return new ComprehensiveAnalysisResult(
          eventFindings,
          failedFiles,
          backdoorScan,
          directoryTree,
          suspiciousFiles,
          combinedCode,
          allPluginResults);

    } catch (IOException e) {
      logger.severe("[" + workerName + "] Analysis failed with IOException: " + e.getMessage());
      e.printStackTrace();
      throw new AnalysisException("Analysis failed", e);
    } catch (Exception e) {
      logger.severe(
          "[" + workerName + "] Analysis failed with unexpected exception: " + e.getMessage());
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
      logger.info(
          "Cache HIT! Reusing decompilation from memory cache for: " + pluginFile.getFileName());
      return cachedResult.get();
    }

    Path cacheDir = Paths.get("decompile_cache");
    Files.createDirectories(cacheDir);
    Path specificCache = cacheDir.resolve(pluginFile.getFileName().toString() + "_" + checksum);

    boolean needsExtraction = !Files.exists(specificCache)
        || !Files.isDirectory(specificCache)
        || isDirEmpty(specificCache);

    if (!needsExtraction) {
      logger.info("Disk cache HIT! Reusing decompiled files from: " + specificCache.getFileName());
      Path decompiledDir = specificCache.resolve("decompiled");
      Files.createDirectories(decompiledDir);

      try (Stream<Path> walk = Files.walk(decompiledDir)) {
        List<Path> javaFiles = walk.filter(p -> p.toString().endsWith(".java")).collect(Collectors.toList());
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
        SafeJavaParser.parse(j)
            .getPrimaryType()
            .ifPresent(
                type -> {
                  type.getFullyQualifiedName()
                      .ifPresent(
                          fqn -> {
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

  private void analyzePluginConfigs(Path workingDir, Map<Path, List<String>> findings) {
    try (Stream<Path> files = Files.walk(workingDir)) {
      files
          .filter(
              p -> {
                String fileName = p.toString();
                return fileName.endsWith(".yml") || fileName.endsWith(".yaml");
              })
          .forEach(
              yamlFile -> {
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
        findings
            .computeIfAbsent(yamlFile, k -> new ArrayList<>())
            .add("MEDIUM: Dangerous command in " + yamlFile.getFileName() + ": " + cmd);
      }
    }
  }

  private String generateDirectoryTree(Path rootDir) {
    StringBuilder tree = new StringBuilder();
    try (Stream<Path> paths = Files.walk(rootDir, 3)) {
      paths
          .filter(Files::isDirectory)
          .limit(50)
          .forEach(
              p -> {
                int depth = rootDir.relativize(p).getNameCount();
                tree.append("  ".repeat(depth)).append("└─ ").append(p.getFileName()).append("/\n");
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
