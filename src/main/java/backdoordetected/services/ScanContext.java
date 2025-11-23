package backdoordetected.services;

import backdoordetected.utils.ScanMode;
import java.nio.file.Path;

public record ScanContext(
        Path pluginPath,
        Path workingDirectory,
        ScanMode scanMode,
        String workerName) {
    public ScanContext {
        if (pluginPath == null) {
            throw new IllegalArgumentException("Plugin path cannot be null");
        }
        if (scanMode == null) {
            throw new IllegalArgumentException("Scan mode cannot be null");
        }
        if (workerName == null || workerName.isBlank()) {
            throw new IllegalArgumentException("Worker name cannot be null or blank");
        }
    }
}
