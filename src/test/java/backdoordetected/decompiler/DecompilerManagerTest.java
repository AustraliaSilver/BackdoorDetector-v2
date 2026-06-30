package backdoordetected.decompiler;

import static org.junit.jupiter.api.Assertions.*;

import backdoordetected.models.DecompilationResult;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class DecompilerManagerTest {

  private DecompilerManager manager;
  private Path tempDir;

  @BeforeEach
  void setUp() throws IOException {
    manager = new DecompilerManager();
    tempDir = Files.createTempDirectory("DecompilerManagerTest");
  }

  @AfterEach
  void tearDown() {
    try (var paths = Files.walk(tempDir)) {
      paths.sorted(Comparator.reverseOrder())
          .forEach(p -> { try { Files.deleteIfExists(p); } catch (IOException ignored) {} });
    } catch (IOException ignored) {}
  }

  @Test
  void decompileWithNonExistentPluginReturnsResult() {
    Path fakeJar = tempDir.resolve("nonexistent.jar");
    // Should not throw - Vineflower handles missing files gracefully
    assertDoesNotThrow(() -> manager.decompile(fakeJar, tempDir));
  }

  @Test
  void decompileWithEmptyJarReturnsNoJavaFiles() throws Exception {
    Path emptyJar = createEmptyJar();
    DecompilationResult result = manager.decompile(emptyJar, tempDir);
    assertNotNull(result);
    assertTrue(result.javaFiles().isEmpty());
    assertEquals(tempDir, result.workingDirectory());
  }

  @Test
  void decompileWithClassFilesButNoVineflowerOutput() throws Exception {
    Path classDir = tempDir.resolve("classes");
    Files.createDirectories(classDir);
    Files.writeString(classDir.resolve("Test.class"), "fake class data");

    Path emptyJar = createEmptyJar();
    DecompilationResult result = manager.decompile(emptyJar, tempDir);
    assertNotNull(result);
  }

  private Path createEmptyJar() throws IOException {
    Path jarPath = tempDir.resolve("empty.jar");
    try (var out = Files.newOutputStream(jarPath);
         var jos = new java.util.jar.JarOutputStream(out)) {
    }
    return jarPath;
  }
}
