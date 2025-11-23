package backdoordetected.detection;


import backdoordetected.utils.StandaloneLogger;
import java.io.IOException;
import java.nio.file.Path;
import java.util.*;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.logging.Logger;

public class LMXBackdoorDetector {
    private static final Logger logger = StandaloneLogger.getLogger();

    public static BackdoorScanResult analyze(Path jarPath) {
        BackdoorScanResult result = new BackdoorScanResult();

        try (JarFile jarFile = new JarFile(jarPath.toFile())) {
            if (hasLMXBackdoor(jarFile)) {
                result.hasLMXBackdoor = true;
                result.findings.add(
                        "CRITICAL: L.M.X backdoor signature detected! Found sequential L/M/X directory structure.");
                logger.warning("[L.M.X DETECTED] " + jarPath.getFileName());
            }

            if (hasOpenEctasyBackdoor(jarFile)) {
                result.hasOpenEctasy = true;
                result.findings.add("CRITICAL: OpenEctasy malware detected! Found 'bodyalhoha' directory signature.");
                logger.warning("[OpenEctasy DETECTED] " + jarPath.getFileName());
            }

        } catch (IOException e) {
            logger.warning(
                    "Failed to scan JAR for backdoor signatures: " + jarPath.getFileName() + " - " + e.getMessage());
        }

        return result;
    }

    private static boolean hasLMXBackdoor(JarFile jarFile) {
        Set<String> directories = extractAllDirectories(jarFile);
        return hasSequentialLMXFolders(directories);
    }

    private static Set<String> extractAllDirectories(JarFile jarFile) {
        Set<String> directories = new HashSet<>();
        Enumeration<JarEntry> entries = jarFile.entries();

        while (entries.hasMoreElements()) {
            JarEntry entry = entries.nextElement();
            String path = entry.getName();

            String[] pathParts = path.split("/");
            StringBuilder currentPath = new StringBuilder();

            for (int i = 0; i < pathParts.length - 1; i++) {
                String part = pathParts[i];
                if (!part.isEmpty()) {
                    currentPath.append(part).append("/");
                    directories.add(currentPath.toString());
                }
            }
        }
        return directories;
    }

    private static boolean hasSequentialLMXFolders(Set<String> directories) {
        for (String dir : directories) {
            String[] parts = dir.split("/");

            for (int i = 0; i < parts.length - 2; i++) {
                if ("L".equalsIgnoreCase(parts[i]) &&
                        "M".equalsIgnoreCase(parts[i + 1]) &&
                        "X".equalsIgnoreCase(parts[i + 2])) {
                    logger.info("Found L.M.X sequence at: " + dir);
                    return true;
                }
            }
        }

        return false;
    }

    private static boolean hasOpenEctasyBackdoor(JarFile jarFile) {
        Enumeration<JarEntry> entries = jarFile.entries();

        while (entries.hasMoreElements()) {
            JarEntry entry = entries.nextElement();
            String path = entry.getName();
            String[] pathParts = path.split("/");

            for (String part : pathParts) {
                if ("bodyalhoha".equalsIgnoreCase(part)) {
                    logger.info("Found OpenEctasy signature: bodyalhoha in " + path);
                    return true;
                }
            }
        }

        return false;
    }

    public static class BackdoorScanResult {
        public boolean hasLMXBackdoor = false;
        public boolean hasOpenEctasy = false;
        public List<String> findings = new ArrayList<>();

        public boolean hasAnyBackdoor() {
            return hasLMXBackdoor || hasOpenEctasy;
        }

        public boolean isCritical() {
            return hasAnyBackdoor();
        }
    }
}
