package backdoordetected.services;

import static org.junit.jupiter.api.Assertions.*;

import backdoordetected.exceptions.AnalysisException;
import backdoordetected.models.ComprehensiveAnalysisResult;
import backdoordetected.utils.ScanMode;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class AnalysisCoordinatorTest {

  private AnalysisCoordinator coordinator;
  private Path tempDir;

  @BeforeEach
  void setUp() throws IOException {
    coordinator = new AnalysisCoordinator();
    tempDir = Files.createTempDirectory("AnalysisCoordinatorTest");
  }

  @AfterEach
  void tearDown() {
    try (var paths = Files.walk(tempDir)) {
      paths.sorted(Comparator.reverseOrder()).forEach(p -> {
        try { Files.deleteIfExists(p); } catch (IOException e) { }
      });
    } catch (IOException e) { }
  }

  @Test
  void analyzeWithNonExistentPluginThrows() {
    Path nonExistent = tempDir.resolve("nonexistent.jar");
    assertThrows(AnalysisException.class, () ->
        coordinator.analyze(nonExistent, ScanMode.BYTECODE, "test-worker"));
  }

  @Test
  void analyzeWithEmptyPluginReturnsEmptyResult() throws Exception {
    Path emptyJar = createEmptyJar(tempDir, "empty");
    ComprehensiveAnalysisResult result = coordinator.analyze(
        emptyJar, ScanMode.BYTECODE, "test-worker");
    assertNotNull(result);
    assertTrue(result.eventFindings().isEmpty());
    assertFalse(result.hasKnownBackdoor());
    assertFalse(result.hasFindings());
  }

  @Test
  void analyzeWithNonJarFileReturnsResult() throws Exception {
    Path notAJar = tempDir.resolve("notajar.jar");
    Files.writeString(notAJar, "not a zip file");
    ComprehensiveAnalysisResult result = coordinator.analyze(
        notAJar, ScanMode.BYTECODE, "test-worker");
    assertNotNull(result);
    assertTrue(result.eventFindings().isEmpty());
  }

  @Test
  void analyzeWithSimpleClassInJarReturnsResult() throws Exception {
    Path jarPath = createJarWithClass(tempDir, "HelloWorld");
    ComprehensiveAnalysisResult result = coordinator.analyze(
        jarPath, ScanMode.BYTECODE, "test-worker");
    assertNotNull(result);
    assertNotNull(result.directoryTree());
  }

  private static Path createEmptyJar(Path dir, String name) throws IOException {
    Path jarPath = dir.resolve(name + ".jar");
    try (OutputStream out = Files.newOutputStream(jarPath);
         java.util.jar.JarOutputStream jos = new java.util.jar.JarOutputStream(out)) {
    }
    return jarPath;
  }

  private static Path createJarWithClass(Path dir, String className) throws IOException {
    Path jarPath = dir.resolve(className + ".jar");
    org.objectweb.asm.ClassWriter cw =
        new org.objectweb.asm.ClassWriter(org.objectweb.asm.ClassWriter.COMPUTE_FRAMES);
    cw.visit(org.objectweb.asm.Opcodes.V1_8,
        org.objectweb.asm.Opcodes.ACC_PUBLIC,
        className, null, "java/lang/Object", null);
    cw.visitEnd();

    try (OutputStream out = Files.newOutputStream(jarPath);
         java.util.jar.JarOutputStream jos = new java.util.jar.JarOutputStream(out)) {
      jos.putNextEntry(new java.util.jar.JarEntry(className + ".class"));
      jos.write(cw.toByteArray());
      jos.closeEntry();
    }
    return jarPath;
  }
}
