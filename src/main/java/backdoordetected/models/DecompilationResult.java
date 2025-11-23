package backdoordetected.models;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;

public record DecompilationResult(
        List<Path> javaFiles,
        Map<Path, Path> javaToClassMap,
        Path workingDirectory) {
}