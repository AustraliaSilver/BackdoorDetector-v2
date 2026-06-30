package backdoordetected;

import static org.junit.jupiter.api.Assertions.*;

import backdoordetected.detection.SootTaintAnalyzer;
import backdoordetected.models.SootAnalysisResult;
import backdoordetected.models.TaintFlow;
import backdoordetected.utils.ScanMode;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import javax.tools.JavaCompiler;
import javax.tools.ToolProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class SootIntegrationTest {

  private SootTaintAnalyzer analyzer;
  private Path tempDir;
  private Path compiledDir;
  private static JavaCompiler javac;
  private static boolean javacAvailable;

  @BeforeAll
  static void checkCompiler() {
    javac = ToolProvider.getSystemJavaCompiler();
    javacAvailable = javac != null;
  }

  @BeforeEach
  void setUp() throws IOException {
    analyzer = new SootTaintAnalyzer();
    tempDir = Files.createTempDirectory("SootIntegrationTest");
    compiledDir = tempDir.resolve("classes");
    Files.createDirectories(compiledDir);
  }

  @AfterEach
  void tearDown() {
    try (var paths = Files.walk(tempDir)) {
      paths.sorted((a, b) -> b.compareTo(a))
          .forEach(p -> { try { Files.deleteIfExists(p); } catch (IOException e) { } });
    } catch (IOException e) { }
  }

  @Test
  void realBackdoorPluginDetectsTaintFlow() throws Exception {
    if (!javacAvailable) return;

    String source = """
        package com.example;
        public class BackdoorPlugin {
            public void onCommand(String[] args) {
                try {
                    Runtime runtime = Runtime.getRuntime();
                    Process proc = runtime.exec(args[0]);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
        """;

    Path jarPath = compileAndJar(source, "com/example/BackdoorPlugin.java", "BackdoorPlugin.jar");

    SootAnalysisResult result = (SootAnalysisResult) analyzer.analyze(
        jarPath, Collections.emptyList(), Collections.emptyList(),
        compiledDir, ScanMode.DATA_FLOW, "test-worker");

    assertFalse(result.taintFlows().isEmpty(),
        "Should detect taint flow from onCommand to Runtime.exec");
    TaintFlow flow = result.taintFlows().get(0);
    assertTrue(flow.source().contains("onCommand"),
        "Source should be onCommand: " + flow.source());
    assertTrue(flow.sink().contains("Runtime.exec"),
        "Sink should be Runtime.exec: " + flow.sink());
    assertEquals("CRITICAL", flow.severity(),
        "Runtime.exec should be CRITICAL severity");
  }

  @Test
  void safePluginDetectsNoTaintFlow() throws Exception {
    if (!javacAvailable) return;

    String source = """
        package com.example;
        public class SafePlugin {
            public void onCommand(String[] args) {
                System.out.println("Hello, " + (args.length > 0 ? args[0] : "world"));
            }
            public int add(int a, int b) {
                return a + b;
            }
        }
        """;

    Path jarPath = compileAndJar(source, "com/example/SafePlugin.java", "SafePlugin.jar");

    SootAnalysisResult result = (SootAnalysisResult) analyzer.analyze(
        jarPath, Collections.emptyList(), Collections.emptyList(),
        compiledDir, ScanMode.DATA_FLOW, "test-worker");

    assertTrue(result.taintFlows().isEmpty(),
        "Safe plugin should have no taint flows");
    assertFalse(result.hasHighSeverityFindings());
    assertTrue(result.errors().isEmpty(), "No errors expected: " + result.errors());
  }

  @Test
  void classForNameDetected() throws Exception {
    if (!javacAvailable) return;

    String source = """
        package com.example;
        public class ClassForNamePlugin {
            public void onCommand(String[] args) {
                try {
                    Class<?> clazz = Class.forName(args[0]);
                } catch (Exception e) {
                }
            }
        }
        """;

    Path jarPath = compileAndJar(source, "com/example/ClassForNamePlugin.java", "ClassForNamePlugin.jar");

    SootAnalysisResult result = (SootAnalysisResult) analyzer.analyze(
        jarPath, Collections.emptyList(), Collections.emptyList(),
        compiledDir, ScanMode.DATA_FLOW, "test-worker");

    boolean hasClassForName = result.taintFlows().stream()
        .anyMatch(f -> f.sink().contains("Class.forName"));
    assertTrue(hasClassForName,
        "Should detect taint flow to Class.forName");
  }

  @Test
  void runtimeExecWithStringArgDetected() throws Exception {
    if (!javacAvailable) return;

    String source = """
        package com.example;
        public class DispatchPlugin {
            public void onCommand(String cmd) {
                try {
                    Runtime.getRuntime().exec(cmd);
                } catch (Exception e) {
                }
            }
        }
        """;

    Path jarPath = compileAndJar(source, "com/example/DispatchPlugin.java", "DispatchPlugin.jar");

    SootAnalysisResult result = (SootAnalysisResult) analyzer.analyze(
        jarPath, Collections.emptyList(), Collections.emptyList(),
        compiledDir, ScanMode.DATA_FLOW, "test-worker");

    assertFalse(result.taintFlows().isEmpty(),
        "Should detect taint flow from onCommand to Runtime.exec");
    TaintFlow flow = result.taintFlows().get(0);
    assertTrue(flow.sink().contains("Runtime.exec"),
        "Sink should reference Runtime.exec: " + flow.sink());
  }

  @Test
  void fakeBackdoorPluginDetectsAllTaintFlows() throws Exception {
    if (!javacAvailable) return;

    String source = """
        package com.example;
        import java.io.*;
        import java.nio.file.*;
        public class FakeBackdoorPlugin {
            public void onCommand(String[] args) {
                execBackdoor(args);
                fileWriteBackdoor(args);
                classLoaderBackdoor(args);
            }
            private void execBackdoor(String[] args) {
                try {
                    Runtime.getRuntime().exec(args[0]);
                } catch (Exception e) { }
            }
            private void fileWriteBackdoor(String[] args) {
                try {
                    Files.writeString(Path.of(args[1]), args[2]);
                } catch (Exception e) { }
            }
            private void classLoaderBackdoor(String[] args) {
                try {
                    Class.forName(args[3]);
                } catch (Exception e) { }
            }
        }
        """;

    Path jarPath = compileAndJar(source, "com/example/FakeBackdoorPlugin.java", "FakeBackdoorPlugin.jar");

    SootAnalysisResult result = (SootAnalysisResult) analyzer.analyze(
        jarPath, Collections.emptyList(), Collections.emptyList(),
        compiledDir, ScanMode.DATA_FLOW, "test-worker");

    assertTrue(result.taintFlows().size() >= 3,
        "Should detect at least 3 taint flows, got " + result.taintFlows().size());

    boolean hasExec = result.taintFlows().stream()
        .anyMatch(f -> f.sink().contains("Runtime.exec"));
    assertTrue(hasExec, "Should detect Runtime.exec backdoor");

    boolean hasFilesWrite = result.taintFlows().stream()
        .anyMatch(f -> f.sink().contains("Files.writeString"));
    assertTrue(hasFilesWrite, "Should detect Files.writeString backdoor");

    boolean hasClassForName = result.taintFlows().stream()
        .anyMatch(f -> f.sink().contains("Class.forName"));
    assertTrue(hasClassForName, "Should detect Class.forName backdoor");
  }

  @Test
  void fakeBackdoorMultipleSinksInOneMethod() throws Exception {
    if (!javacAvailable) return;

    String source = """
        package com.example;
        import java.io.*;
        public class MultiSinkPlugin {
            public void onCommand(String[] args) {
                try {
                    Runtime rt = Runtime.getRuntime();
                    rt.exec(args[0]);
                    FileWriter fw = new FileWriter(args[1]);
                    fw.write("data");
                    fw.close();
                } catch (Exception e) {
                }
            }
        }
        """;

    Path jarPath = compileAndJar(source, "com/example/MultiSinkPlugin.java", "MultiSinkPlugin.jar");

    SootAnalysisResult result = (SootAnalysisResult) analyzer.analyze(
        jarPath, Collections.emptyList(), Collections.emptyList(),
        compiledDir, ScanMode.DATA_FLOW, "test-worker");

    assertTrue(result.taintFlows().size() >= 2,
        "Should detect at least 2 taint flows, got " + result.taintFlows().size());

    boolean hasExec = result.taintFlows().stream()
        .anyMatch(f -> f.sink().contains("Runtime.exec"));
    assertTrue(hasExec, "Should detect Runtime.exec");

    boolean hasFileWriter = result.taintFlows().stream()
        .anyMatch(f -> f.sink().contains("FileWriter"));
    assertTrue(hasFileWriter, "Should detect FileWriter backdoor");
  }

  @Test
  void fakeBackdoorWithObfuscatedSinkPatterns() throws Exception {
    if (!javacAvailable) return;

    String source = """
        package com.example;
        public class ObfuscatedBackdoor {
            public void onCommand(String[] args) {
                exec(args[0]);
            }
            private void exec(String cmd) {
                try {
                    execIndirect(cmd);
                } catch (Exception e) { }
            }
            private void execIndirect(String cmd) throws Exception {
                Runtime.getRuntime().exec(cmd);
            }
        }
        """;

    Path jarPath = compileAndJar(source, "com/example/ObfuscatedBackdoor.java", "ObfuscatedBackdoor.jar");

    SootAnalysisResult result = (SootAnalysisResult) analyzer.analyze(
        jarPath, Collections.emptyList(), Collections.emptyList(),
        compiledDir, ScanMode.DATA_FLOW, "test-worker");

    assertFalse(result.taintFlows().isEmpty(),
        "Should detect taint flow through call chain");
    assertTrue(result.taintFlows().get(0).sink().contains("Runtime.exec"),
        "Sink should be Runtime.exec: " + result.taintFlows().get(0).sink());
  }

  private Path compileAndJar(String source, String sourcePath, String jarName) throws IOException {
    Path srcFile = tempDir.resolve(sourcePath);
    Files.createDirectories(srcFile.getParent());
    Files.writeString(srcFile, source);

    int exitCode = javac.run(null, null, null,
        "-d", compiledDir.toAbsolutePath().toString(),
        srcFile.toAbsolutePath().toString());
    assertEquals(0, exitCode, "Compilation should succeed");

    Path jarPath = tempDir.resolve(jarName);
    try (OutputStream out = Files.newOutputStream(jarPath);
         JarOutputStream jos = new JarOutputStream(out)) {
      Files.walk(compiledDir).filter(Files::isRegularFile).forEach(classFile -> {
        String entryName = compiledDir.relativize(classFile).toString()
            .replace('\\', '/');
        try {
          jos.putNextEntry(new JarEntry(entryName));
          Files.copy(classFile, jos);
          jos.closeEntry();
        } catch (IOException e) {
          throw new RuntimeException(e);
        }
      });
    }
    return jarPath;
  }
}
