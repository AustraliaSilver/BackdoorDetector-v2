package backdoordetected;

import static org.junit.jupiter.api.Assertions.*;

import backdoordetected.services.PluginOrchestrator;
import backdoordetected.services.ServiceFactory;
import backdoordetected.utils.ScanMode;
import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class PluginOrchestratorIntegrationTest {

  @TempDir
  File tempDir;

  @BeforeEach
  void setUp() {
  }

  private Path createDecoyPlugin(String name, String source)
      throws IOException, InterruptedException {
    File decoySrc = new File(tempDir, name + ".java");
    try (java.io.FileWriter writer = new java.io.FileWriter(decoySrc)) {
      writer.write(source);
    }

    javax.tools.JavaCompiler compiler = javax.tools.ToolProvider.getSystemJavaCompiler();
    compiler.run(null, null, null, decoySrc.getAbsolutePath());

    Path decoyJarPath = new File(tempDir, name + ".jar").toPath();
    ProcessBuilder pb = new ProcessBuilder(
        "jar",
        "-cf",
        decoyJarPath.toAbsolutePath().toString(),
        "-C",
        tempDir.getAbsolutePath(),
        name + ".class");
    pb.directory(tempDir);
    Process process = pb.start();
    process.waitFor();
    return decoyJarPath;
  }

  @Test
  void testScanFindsDirectBackdoor() throws Exception {
    String source = "public class DirectBackdoor { public void run() { try { Runtime.getRuntime().exec(\"calc.exe\"); } catch (Exception e) {} } }";
    Path decoyJarPath = createDecoyPlugin("DirectBackdoor", source);
    PluginOrchestrator orchestrator = ServiceFactory.createPluginOrchestrator(ScanMode.BYTECODE);
    String result = orchestrator.scan(decoyJarPath, ScanMode.BYTECODE, "test-worker-direct");
    assertNotNull(result);
    assertTrue(
        result.contains("CRITICAL: Executes system commands"),
        "The report should contain a finding about Runtime.exec");
  }

  @Test
  void testScanFindsReflectionBackdoor() throws Exception {
    String source = "public class ReflectionBackdoor {"
        + "  public void run() throws Exception {"
        + "    Object runtime = Class.forName(\"java.lang.Runtime\").getMethod(\"getRuntime\").invoke(null);"
        + "    runtime.getClass().getMethod(\"exec\", String.class).invoke(runtime, \"calc.exe\");"
        + "  }"
        + "}";
    Path decoyJarPath = createDecoyPlugin("ReflectionBackdoor", source);
    PluginOrchestrator orchestrator = ServiceFactory.createPluginOrchestrator(ScanMode.BYTECODE);
    String result = orchestrator.scan(decoyJarPath, ScanMode.BYTECODE, "test-worker-reflection");
    assertNotNull(result);
    assertTrue(
        result.contains("HIGH: Uses reflection, could be hiding malicious calls"),
        "The report should contain a finding about Method.invoke");
  }
}
