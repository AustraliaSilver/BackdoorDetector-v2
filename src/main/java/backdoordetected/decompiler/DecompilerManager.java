package backdoordetected.decompiler;

import backdoordetected.models.DecompilationResult;
import backdoordetected.utils.StandaloneLogger;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.jetbrains.java.decompiler.main.Fernflower;
import org.jetbrains.java.decompiler.main.decompiler.DirectoryResultSaver;
import org.jetbrains.java.decompiler.main.extern.IFernflowerLogger;

public class DecompilerManager {
  private static final Logger logger = StandaloneLogger.getLogger();

  public DecompilerManager() {
  }

  public DecompilationResult decompile(Path pluginFile, Path workingDir) throws IOException {
    List<Path> allClassFiles = extractClassFiles(workingDir);

    Path vineflowerOutputDir = workingDir.resolve("decompiled_vineflower");
    List<Path> vineflowerJavaFiles;
    try {
      runVineflower(pluginFile, vineflowerOutputDir);
      vineflowerJavaFiles = collectJavaFiles(vineflowerOutputDir);
    } catch (Exception e) {
      logger.log(Level.SEVERE, "Vineflower decompilation failed catastrophically.", e);
      vineflowerJavaFiles = new ArrayList<>();
    }

    List<Path> failedClassFiles = findFailedFiles(allClassFiles, vineflowerJavaFiles, workingDir);
    if (!failedClassFiles.isEmpty()) {
      logger.warning(
          "Vineflower failed on "
              + failedClassFiles.size()
              + " files. No fallback decompiler configured.");
    }

    List<Path> allJavaFiles = new ArrayList<>(vineflowerJavaFiles);

    logger.info(
        "Decompilation complete. Total Java files: "
            + allJavaFiles.size()
            + " (Vineflower: "
            + vineflowerJavaFiles.size()
            + ")");

    return new DecompilationResult(allJavaFiles, new HashMap<>(), workingDir);
  }

  private void runVineflower(Path pluginFile, Path outputDir) throws Exception {
    logger.info("Running Vineflower decompiler...");
    Files.createDirectories(outputDir);
    Map<String, Object> options = new HashMap<>();
    options.put("dgs", "1");
    options.put("rsy", "1");
    options.put("ind", "    ");
    options.put("log", "info");
    options.put("lit", "1");
    options.put("asc", "1");
    options.put("nls", "1");

    IFernflowerLogger vineLogger = new IFernflowerLogger() {
      @Override
      public void writeMessage(String message, Severity severity) {
        if (severity.ordinal() >= Severity.WARN.ordinal())
          logger.warning("[Vineflower] " + message);
      }

      @Override
      public void writeMessage(String message, Severity severity, Throwable t) {
        logger.log(Level.WARNING, "[Vineflower] " + message, t);
      }
    };

    Fernflower engine = new Fernflower(new DirectoryResultSaver(outputDir.toFile()), options, vineLogger);
    engine.addSource(pluginFile.toFile());
    engine.decompileContext();
  }

  private List<Path> findFailedFiles(
      List<Path> allClassFiles, List<Path> decompiledJavaFiles, Path workingDir) {
    var decompiledNames = decompiledJavaFiles.stream()
        .map(p -> p.getFileName().toString().replace(".java", ""))
        .collect(Collectors.toSet());

    return allClassFiles.stream()
        .filter(
            classFile -> {
              String className = classFile.getFileName().toString().replace(".class", "");
              String mainClassName = className.contains("$")
                  ? className.substring(0, className.indexOf('$'))
                  : className;
              return !decompiledNames.contains(mainClassName);
            })
        .collect(Collectors.toList());
  }

  private List<Path> extractClassFiles(Path workingDir) throws IOException {
    try (Stream<Path> stream = Files.walk(workingDir)) {
      return stream.filter(p -> p.toString().endsWith(".class")).collect(Collectors.toList());
    }
  }

  private List<Path> collectJavaFiles(Path outputDir) throws IOException {
    if (!Files.exists(outputDir))
      return new ArrayList<>();
    try (Stream<Path> stream = Files.walk(outputDir)) {
      return stream.filter(p -> p.toString().endsWith(".java")).collect(Collectors.toList());
    }
  }

  private List<Path> findLibraryPaths() {
    List<Path> libs = new ArrayList<>();
    String javaHome = System.getProperty("java.home");
    if (javaHome != null) {
      Path jmods = Path.of(javaHome, "jmods");
      if (Files.isDirectory(jmods)) {
        try (Stream<Path> stream = Files.walk(jmods)) {
          stream.filter(p -> p.toString().endsWith(".jmod")).forEach(libs::add);
        } catch (IOException e) {
          logger.warning("Could not read jmods directory: " + e.getMessage());
        }
      }
    }

    String classpath = System.getProperty("java.class.path");
    String separator = System.getProperty("path.separator");
    Arrays.stream(classpath.split(separator))
        .filter(p -> p.endsWith(".jar"))
        .map(Path::of)
        .forEach(libs::add);
    return libs;
  }
}
