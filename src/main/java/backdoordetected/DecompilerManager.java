package backdoordetected;

import org.jetbrains.java.decompiler.main.Fernflower;
import org.jetbrains.java.decompiler.main.decompiler.DirectoryResultSaver;
import org.jetbrains.java.decompiler.main.extern.IFernflowerLogger;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class DecompilerManager {
    private static final Logger logger = StandaloneLogger.getLogger();
    private final KrakatauDecompiler krakatauDecompiler;

    public DecompilerManager() {
        this.krakatauDecompiler = new KrakatauDecompiler();
    }

    public PluginWorker.DecompilationResult decompile(Path pluginFile, Path workingDir) throws IOException {
        List<Path> allClassFiles = extractClassFiles(workingDir);

        Path vineflowerOutputDir = workingDir.resolve("decompiled_vineflower");
        runVineflower(pluginFile, vineflowerOutputDir);
        List<Path> vineflowerJavaFiles = collectJavaFiles(vineflowerOutputDir);

        List<Path> failedClassFiles = findFailedFiles(allClassFiles, vineflowerJavaFiles, workingDir);

        List<Path> krakatauJavaFiles = new ArrayList<>();
        if (!failedClassFiles.isEmpty() && krakatauDecompiler.isConfigured()) {
            logger.info("Vineflower failed on " + failedClassFiles.size() + " files. Falling back to Krakatau...");
            Path krakatauOutputDir = workingDir.resolve("decompiled_krakatau");
            Files.createDirectories(krakatauOutputDir);
            krakatauJavaFiles = krakatauDecompiler.decompile(failedClassFiles, krakatauOutputDir);
        } else if (!failedClassFiles.isEmpty()) {
            logger.warning("Krakatau path not configured. Skipping fallback for " + failedClassFiles.size() + " files.");
        }

        List<Path> allJavaFiles = Stream.concat(vineflowerJavaFiles.stream(), krakatauJavaFiles.stream())
                .collect(Collectors.toList());

        logger.info("Decompilation complete. Total Java files: " + allJavaFiles.size()
                + " (Vineflower: " + vineflowerJavaFiles.size()
                + ", Krakatau: " + krakatauJavaFiles.size() + ")");

        return new PluginWorker.DecompilationResult(allJavaFiles, new HashMap<>(), workingDir);
    }

    private void runVineflower(Path pluginFile, Path outputDir) throws IOException {
        logger.info("Running Vineflower decompiler...");
        Files.createDirectories(outputDir);
        Map<String, Object> options = Map.of("dgs", "1", "rsy", "1", "ind", "    ", "log", "warn");

        IFernflowerLogger vineLogger = new IFernflowerLogger() {
            @Override
            public void writeMessage(String message, Severity severity) {
                if (severity.ordinal() >= Severity.WARN.ordinal()) logger.warning("[Vineflower] " + message);
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

    private List<Path> findFailedFiles(List<Path> allClassFiles, List<Path> decompiledJavaFiles, Path workingDir) {
        var decompiledNames = decompiledJavaFiles.stream()
                .map(p -> p.getFileName().toString().replace(".java", ""))
                .collect(Collectors.toSet());

        return allClassFiles.stream()
                .filter(classFile -> {
                    String className = classFile.getFileName().toString().replace(".class", "");
                    String mainClassName = className.contains("$") ? className.substring(0, className.indexOf('$')) : className;
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
        if (!Files.exists(outputDir)) return new ArrayList<>();
        try (Stream<Path> stream = Files.walk(outputDir)) {
            return stream.filter(p -> p.toString().endsWith(".java")).collect(Collectors.toList());
        }
    }
}