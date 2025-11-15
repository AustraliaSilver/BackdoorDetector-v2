package backdoordetected;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;
import java.util.stream.Collectors;

public class KrakatauDecompiler {
    private static final Logger logger = StandaloneLogger.getLogger();
    private Path krakatauScriptPath;
    private boolean isConfigured = false;

    public KrakatauDecompiler() {
        try {
            this.krakatauScriptPath = extractAndGetScriptPath();
            this.isConfigured = true;
        } catch (IOException | URISyntaxException e) {
            logger.warning("Could not extract embedded Krakatau decompiler: " + e.getMessage());
            this.isConfigured = false;
        }
    }

    public boolean isConfigured() {
        return this.isConfigured;
    }

    public List<Path> decompile(List<Path> classFiles, Path outputDir) {
        if (!isConfigured()) {
            logger.warning("Krakatau path not set. Cannot perform fallback decompilation.");
            return new ArrayList<>();
        }

        List<Path> successfulFiles = new ArrayList<>();
        for (Path classFile : classFiles) {
            try {
                ProcessBuilder pb = new ProcessBuilder(
                        "python",
                        krakatauScriptPath.toAbsolutePath().toString(),
                        "-out", outputDir.toAbsolutePath().toString(),
                        classFile.toAbsolutePath().toString()
                );
                pb.redirectErrorStream(true);

                logger.info("[Krakatau] Decompiling: " + classFile.getFileName());
                Process process = pb.start();

                try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        logger.fine("[Krakatau] " + line);
                    }
                }

                if (!process.waitFor(60, TimeUnit.SECONDS)) {
                    process.destroyForcibly();
                    logger.warning("[Krakatau] Timed out while decompiling " + classFile.getFileName());
                } else if (process.exitValue() == 0) {
                }
            } catch (IOException | InterruptedException e) {
                logger.severe("[Krakatau] Error decompiling " + classFile.getFileName() + ": " + e.getMessage());
            }
        }
        try (var stream = Files.walk(outputDir)) {
            return stream.filter(p -> p.toString().endsWith(".java")).collect(Collectors.toList());
        } catch (IOException e) {
            logger.severe("[Krakatau] Failed to collect decompiled files: " + e.getMessage());
            return new ArrayList<>();
        }
    }

    private Path extractAndGetScriptPath() throws IOException, URISyntaxException {
        Path tempDir = Files.createTempDirectory("krakatau-embedded-");
        tempDir.toFile().deleteOnExit();

        String resourcePath = "krakatau";

        List<String> krakatauFiles = List.of(
            "decompile.py",
            "Krakatau/__init__.py",
            "Krakatau/classfile.py",
            "Krakatau/decompiler.py",
            "Krakatau/ssa.py",
            "Krakatau/struct.py"
        );

        for (String fileName : krakatauFiles) {
            Path destination = tempDir.resolve(fileName);
            Files.createDirectories(destination.getParent());
            try (InputStream is = getClass().getClassLoader().getResourceAsStream(resourcePath + "/" + fileName)) {
                if (is == null) throw new IOException("Cannot find resource: " + resourcePath + "/" + fileName);
                Files.copy(is, destination);
            }
        }

        logger.info("Embedded Krakatau extracted to: " + tempDir);
        return tempDir.resolve("decompile.py");
    }
}