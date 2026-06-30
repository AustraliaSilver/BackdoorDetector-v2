package backdoordetected.utils;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;

class FileUtilsTest {

  @Test
  void deleteDirectoryWithNullDoesNothing() {
    FileUtils.deleteDirectory(null);
  }

  @Test
  void deleteDirectoryWithNonExistentPathDoesNothing() {
    FileUtils.deleteDirectory(Path.of("nonexistent_path_12345"));
  }

  @Test
  void deleteDirectoryDeletesFile() throws IOException {
    Path tempFile = Files.createTempFile("FileUtilsTest", ".tmp");
    assertTrue(Files.exists(tempFile));
    FileUtils.deleteDirectory(tempFile);
    assertFalse(Files.exists(tempFile));
  }

  @Test
  void deleteDirectoryDeletesDirectoryWithContents() throws IOException {
    Path tempDir = Files.createTempDirectory("FileUtilsTestDir");
    Path subFile = tempDir.resolve("test.txt");
    Files.writeString(subFile, "hello");
    Path subDir = tempDir.resolve("sub");
    Files.createDirectory(subDir);

    FileUtils.deleteDirectory(tempDir);
    assertFalse(Files.exists(tempDir));
  }

  @Test
  void printProgressWithZeroTotalDoesNothing() {
    FileUtils.printProgress("test", 0, 0, System.nanoTime());
  }

  @Test
  void printProgressCompletesWithoutError() {
    long startTime = System.nanoTime();
    FileUtils.printProgress("test", 10, 100, startTime);
    FileUtils.printProgress("test", 100, 100, startTime);
  }
}
