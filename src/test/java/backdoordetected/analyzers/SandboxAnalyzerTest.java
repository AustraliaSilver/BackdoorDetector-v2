package backdoordetected.analyzers;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class SandboxAnalyzerTest {

  private SandboxAnalyzer analyzer;
  private Path tempDir;

  @BeforeEach
  void setUp() throws IOException {
    analyzer = new SandboxAnalyzer();
    tempDir = Files.createTempDirectory("SandboxTest");
  }

  private Path writeJavaFile(String fileName, String content) throws IOException {
    Path file = tempDir.resolve(fileName);
    Files.writeString(file, content);
    return file;
  }

  @Test
  void analyzeWithNoFilesReturnsEmpty() {
    Map<String, List<String>> results = analyzer.analyze(List.of());
    assertTrue(results.isEmpty());
  }

  @Test
  void analyzeWithCleanFileReturnsEmpty() throws IOException {
    writeJavaFile("Clean.java", """
        public class Clean {
            public void doSomething() {
                System.out.println("ok");
            }
        }
        """);
    Map<String, List<String>> results = analyzer.analyze(List.of(tempDir.resolve("Clean.java")));
    assertTrue(results.isEmpty());
  }

  @Test
  void analyzeWithSetOpInEventHandlerDetectsIt() throws IOException {
    writeJavaFile("SetOpPlugin.java", """
        import org.bukkit.event.EventHandler;
        import org.bukkit.event.player.PlayerJoinEvent;
        public class SetOpPlugin {
            @EventHandler
            public void onJoin(PlayerJoinEvent e) {
                e.getPlayer().setOp(true);
            }
        }
        """);
    Map<String, List<String>> results = analyzer.analyze(
        List.of(tempDir.resolve("SetOpPlugin.java")));
    boolean foundOp = results.values().stream()
        .flatMap(List::stream)
        .anyMatch(f -> f.contains("OP"));
    assertTrue(foundOp);
  }

  @Test
  void analyzeWithExecInEventHandlerDetectsIt() throws IOException {
    writeJavaFile("ExecPlugin.java", """
        import org.bukkit.event.EventHandler;
        import org.bukkit.event.player.PlayerJoinEvent;
        public class ExecPlugin {
            @EventHandler
            public void onJoin(PlayerJoinEvent e) {
                Runtime.getRuntime().exec("calc");
            }
        }
        """);
    Map<String, List<String>> results = analyzer.analyze(
        List.of(tempDir.resolve("ExecPlugin.java")));
    boolean foundExec = results.values().stream()
        .flatMap(List::stream)
        .anyMatch(f -> f.contains("Executes system commands"));
    assertTrue(foundExec);
  }

  @Test
  void analyzeWithReflectionInvokeDetectsIt() throws IOException {
    writeJavaFile("ReflectPlugin.java", """
        import org.bukkit.event.EventHandler;
        import org.bukkit.event.player.PlayerJoinEvent;
        public class ReflectPlugin {
            @EventHandler
            public void onJoin(PlayerJoinEvent e) throws Exception {
                Class.forName("evil").getMethod("doit").invoke(null);
            }
        }
        """);
    Map<String, List<String>> results = analyzer.analyze(
        List.of(tempDir.resolve("ReflectPlugin.java")));
    boolean foundInvoke = results.values().stream()
        .flatMap(List::stream)
        .anyMatch(f -> f.contains("reflection"));
    assertTrue(foundInvoke);
  }

  @Test
  void analyzeWithNonEventHandlerDoesNotDetect() throws IOException {
    writeJavaFile("Normal.java", """
        public class Normal {
            public void setOp(boolean op) {
                System.out.println("Not an event handler");
            }
        }
        """);
    Map<String, List<String>> results = analyzer.analyze(
        List.of(tempDir.resolve("Normal.java")));
    assertTrue(results.isEmpty());
  }

  @Test
  void analyzeWithNonExistentFileReturnsEmpty() {
    Map<String, List<String>> results = analyzer.analyze(
        List.of(tempDir.resolve("nonexistent.java")));
    assertTrue(results.isEmpty());
  }
}
