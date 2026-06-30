package backdoordetected.analyzers;

import static org.junit.jupiter.api.Assertions.*;

import backdoordetected.models.EventTriggerAnalysisResult;
import backdoordetected.utils.ScanMode;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class EventTriggerAnalyzerTest {

  private EventTriggerAnalyzer analyzer;
  private Path tempDir;

  @BeforeEach
  void setUp() throws IOException {
    analyzer = new EventTriggerAnalyzer();
    tempDir = Files.createTempDirectory("EventTriggerTest");
  }

  private Path writeJavaFile(String fileName, String content) throws IOException {
    Path file = tempDir.resolve(fileName);
    Files.writeString(file, content);
    return file;
  }

  @Test
  void analyzeWithNoFilesReturnsEmptyResult() throws Exception {
    EventTriggerAnalysisResult result = (EventTriggerAnalysisResult) analyzer.analyze(
        tempDir.resolve("dummy.jar"), List.of(), List.of(), tempDir, ScanMode.BYTECODE, "test");
    assertNotNull(result);
    assertTrue(result.getFileFindings().isEmpty());
    assertFalse(result.hasHighSeverityFindings());
  }

  @Test
  void analyzeWithCleanJavaFileReturnsNoFindings() throws Exception {
    writeJavaFile("CleanPlugin.java", """
        public class CleanPlugin {
            public void onEnable() {
                System.out.println("Hello");
            }
        }
        """);

    List<Path> javaFiles = List.of(tempDir.resolve("CleanPlugin.java"));

    EventTriggerAnalysisResult result = (EventTriggerAnalysisResult) analyzer.analyze(
        tempDir.resolve("p.jar"), javaFiles, List.of(), tempDir, ScanMode.BYTECODE, "test");
    assertTrue(result.getFileFindings().isEmpty());
  }

  @Test
  void analyzeWithDispatchCommandInEventHandlerFindsIt() throws Exception {
    writeJavaFile("BadPlugin.java", """
        import org.bukkit.event.EventHandler;
        import org.bukkit.event.player.PlayerJoinEvent;
        public class BadPlugin {
            @EventHandler
            public void onJoin(PlayerJoinEvent e) {
                dispatchCommand("ban %player%");
            }
            void dispatchCommand(String cmd) {}
        }
        """);

    List<Path> javaFiles = List.of(tempDir.resolve("BadPlugin.java"));
    EventTriggerAnalysisResult result = (EventTriggerAnalysisResult) analyzer.analyze(
        tempDir.resolve("p.jar"), javaFiles, List.of(), tempDir, ScanMode.BYTECODE, "test");
    assertFalse(result.getFileFindings().isEmpty());
    boolean hasDispatch = result.getFileFindings().values().stream()
        .flatMap(List::stream)
        .anyMatch(f -> f.contains("dispatchCommand"));
    assertTrue(hasDispatch);
  }

  @Test
  void analyzeWithSetOpInEventHandlerDetectsIt() throws Exception {
    writeJavaFile("OpPlugin.java", """
        import org.bukkit.event.EventHandler;
        import org.bukkit.event.player.PlayerJoinEvent;
        public class OpPlugin {
            @EventHandler
            public void onJoin(PlayerJoinEvent e) {
                e.getPlayer().setOp(true);
            }
        }
        """);

    List<Path> javaFiles = List.of(tempDir.resolve("OpPlugin.java"));
    EventTriggerAnalysisResult result = (EventTriggerAnalysisResult) analyzer.analyze(
        tempDir.resolve("p.jar"), javaFiles, List.of(), tempDir, ScanMode.BYTECODE, "test");
    boolean hasSetOp = result.getFileFindings().values().stream()
        .flatMap(List::stream)
        .anyMatch(f -> f.contains("setOp"));
    assertTrue(hasSetOp);
  }

  @Test
  void analyzeWithSyntaxErrorRecordsFailedFile() throws Exception {
    writeJavaFile("Broken.java", "public class Broken { this is not valid java }");

    List<Path> javaFiles = List.of(tempDir.resolve("Broken.java"));
    EventTriggerAnalysisResult result = (EventTriggerAnalysisResult) analyzer.analyze(
        tempDir.resolve("p.jar"), javaFiles, List.of(), tempDir, ScanMode.BYTECODE, "test");
    assertEquals(1, result.getFailedFiles().size());
    assertTrue(result.getFailedFiles().get(0).endsWith("Broken.java"));
  }

  @Test
  void analyzeWithMultipleCleanFilesReturnsNoFindings() throws Exception {
    writeJavaFile("A.java", "public class A {}");
    writeJavaFile("B.java", "public class B {}");
    writeJavaFile("C.java", "public class C {}");

    List<Path> javaFiles = List.of(
        tempDir.resolve("A.java"),
        tempDir.resolve("B.java"),
        tempDir.resolve("C.java"));
    EventTriggerAnalysisResult result = (EventTriggerAnalysisResult) analyzer.analyze(
        tempDir.resolve("p.jar"), javaFiles, List.of(), tempDir, ScanMode.BYTECODE, "test");
    assertTrue(result.getFileFindings().isEmpty());
  }

  @Test
  void getNameReturnsCorrectName() {
    assertEquals("EventTriggerAnalyzer", analyzer.getName());
  }
}
