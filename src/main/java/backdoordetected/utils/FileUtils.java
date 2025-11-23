package backdoordetected.utils;

import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.logging.Logger;

public class FileUtils {
    private static final Logger logger = StandaloneLogger.getLogger();

    public static void deleteDirectory(Path path) {
        if (path == null || !Files.exists(path)) {
            return;
        }
        try {
            Files.walkFileTree(path, new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                    Files.delete(file);
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult postVisitDirectory(Path dir, IOException exc) throws IOException {
                    Files.delete(dir);
                    return FileVisitResult.CONTINUE;
                }
            });
            logger.info("Deleted temporary directory: " + path.getFileName());
        } catch (IOException e) {
            logger.warning("Failed to delete temporary directory: " + path + " - " + e.getMessage());
        }
    }

    public static void printProgress(String phase, int processed, int total, long startTime) {
        if (total == 0) return;
        int progress = (processed * 100) / total;
        if (processed % (Math.max(1, total / 20)) == 0 || processed == total) {
            long elapsedTimeNs = System.nanoTime() - startTime;
            String etaString = "";
            if (processed > 0 && elapsedTimeNs > 0) {
                double timePerFile = (double) elapsedTimeNs / processed;
                long remainingFiles = total - processed;
                long etaSeconds = (long) ((remainingFiles * timePerFile) / 1_000_000_000);
                etaString = String.format("ETA: ~%ds", etaSeconds);
            }
            System.out.printf("\r[Progress] %s: %d%% (%d/%d) %s", phase, progress, processed, total, etaString);
        }
    }
}