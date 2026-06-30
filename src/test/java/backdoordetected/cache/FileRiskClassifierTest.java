package backdoordetected.cache;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class FileRiskClassifierTest {

  @TempDir
  Path tempDir;

  @Test
  void testFileIsSkipped() throws IOException {
    Path testFile = tempDir.resolve("MyTest.java");
    Files.writeString(testFile, """
        import org.junit.Test;
        public class MyTest {
            @Test
            public void testSomething() {}
        }
        """);
    assertEquals(FileRiskClassifier.RiskLevel.SKIP, FileRiskClassifier.classifyFile(testFile));
  }

  @Test
  void testFileByPathIsSkipped() throws IOException {
    Path testDir = tempDir.resolve("src/test/java");
    Files.createDirectories(testDir);
    Path testFile = testDir.resolve("PluginTest.java");
    Files.writeString(testFile, "public class PluginTest {}");
    assertEquals(FileRiskClassifier.RiskLevel.SKIP, FileRiskClassifier.classifyFile(testFile));
  }

  @Test
  void generatedCodeIsSkipped() throws IOException {
    Path genFile = tempDir.resolve("Generated.java");
    Files.writeString(genFile, "// Auto-generated file\npublic class Generated {}");
    assertEquals(FileRiskClassifier.RiskLevel.SKIP, FileRiskClassifier.classifyFile(genFile));
  }

  @Test
  void listenerFileIsHighRisk() throws IOException {
    Path listenerFile = tempDir.resolve("EventHandler.java");
    Files.writeString(listenerFile, """
        import org.bukkit.event.Listener;
        public class EventHandler implements Listener {
            public void onPlayerJoin() {}
        }
        """);
    assertEquals(FileRiskClassifier.RiskLevel.HIGH, FileRiskClassifier.classifyFile(listenerFile));
  }

  @Test
  void commandExecutorFileIsHighRisk() throws IOException {
    Path cmdFile = tempDir.resolve("CmdExecutor.java");
    Files.writeString(cmdFile, """
        public class CmdExecutor implements CommandExecutor {
            public boolean onCommand() { return true; }
        }
        """);
    assertEquals(FileRiskClassifier.RiskLevel.HIGH, FileRiskClassifier.classifyFile(cmdFile));
  }

  @Test
  void runtimeExecFileIsHighRisk() throws IOException {
    Path evilFile = tempDir.resolve("Evil.java");
    Files.writeString(evilFile, """
        public class Evil {
            public void run() throws Exception {
                Runtime.getRuntime().exec("calc");
            }
        }
        """);
    assertEquals(FileRiskClassifier.RiskLevel.HIGH, FileRiskClassifier.classifyFile(evilFile));
  }

  @Test
  void simpleClassWithNoDangerIsMediumRisk() throws IOException {
    Path normalFile = tempDir.resolve("Helper.java");
    Files.writeString(normalFile, """
        public class Helper {
            private String name;
            public String getName() { return name; }
            public void setName(String n) { this.name = n; }
        }
        """);
    assertEquals(FileRiskClassifier.RiskLevel.MEDIUM, FileRiskClassifier.classifyFile(normalFile));
  }

  @Test
  void mediumRiskIsDefault() throws IOException {
    Path normalFile = tempDir.resolve("Util.java");
    Files.writeString(normalFile, """
        public class Util {
            public static String format(String input) {
                return input.trim();
            }
        }
        """);
    assertEquals(FileRiskClassifier.RiskLevel.MEDIUM, FileRiskClassifier.classifyFile(normalFile));
  }

  @Test
  void statsRecordsCorrectly() {
    FileRiskClassifier.Stats stats = new FileRiskClassifier.Stats();
    stats.record(FileRiskClassifier.RiskLevel.HIGH);
    stats.record(FileRiskClassifier.RiskLevel.MEDIUM);
    stats.record(FileRiskClassifier.RiskLevel.LOW);
    stats.record(FileRiskClassifier.RiskLevel.SKIP);
    assertEquals(4, stats.total());
    assertEquals(3, stats.analyzed());
    assertTrue(stats.toString().contains("4 total"));
  }
}
