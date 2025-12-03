package backdoordetected.detection;

import static org.junit.jupiter.api.Assertions.*;

import backdoordetected.models.SootAnalysisResult;
import backdoordetected.models.TaintFlow;
import backdoordetected.utils.ScanMode;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

class SootTaintAnalyzerTest implements Opcodes {

  private SootTaintAnalyzer analyzer;
  private Path decoyJarPath;
  @TempDir
  File classDir;

  @BeforeEach
  void setUp() throws IOException {
    analyzer = new SootTaintAnalyzer();
    new File("target/test-jars").mkdirs();
    decoyJarPath = new File("target/test-jars/decoy-soot.jar").toPath();
  }

  private void createDecoyJar() throws IOException {
    ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES);
    cw.visit(V1_8, ACC_PUBLIC, "com/example/DecoyPlugin", null, "java/lang/Object", null);
    MethodVisitor mv = cw.visitMethod(ACC_PUBLIC, "onCommand", "(Ljava/lang/String;)V", null, null);
    mv.visitCode();
    mv.visitMethodInsn(
        INVOKESTATIC, "java/lang/Runtime", "getRuntime", "()Ljava/lang/Runtime;", false);
    mv.visitVarInsn(ALOAD, 1);
    mv.visitMethodInsn(
        INVOKEVIRTUAL,
        "java/lang/Runtime",
        "exec",
        "(Ljava/lang/String;)Ljava/lang/Process;",
        false);
    mv.visitInsn(RETURN);
    mv.visitMaxs(2, 2);
    mv.visitEnd();
    cw.visitEnd();
    Path classFilePath = classDir.toPath().resolve("com/example/DecoyPlugin.class");
    Files.createDirectories(classFilePath.getParent());
    Files.write(classFilePath, cw.toByteArray());
    ProcessBuilder pb = new ProcessBuilder(
        "jar",
        "-cf",
        decoyJarPath.toAbsolutePath().toString(),
        "-C",
        classDir.getAbsolutePath(),
        ".");
    pb.directory(classDir);
    Process process = pb.start();
    try {
      try (var reader = new java.io.BufferedReader(new java.io.InputStreamReader(process.getInputStream()))) {
        while (reader.readLine() != null) {
        }
      }
      try (var reader = new java.io.BufferedReader(new java.io.InputStreamReader(process.getErrorStream()))) {
        while (reader.readLine() != null) {
        }
      }
      process.waitFor();
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    }
  }

  @Test
  void testAnalyzesTaintFlowInDecoyJar() throws Exception {
    createDecoyJar();
    SootAnalysisResult result = (SootAnalysisResult) analyzer.analyze(
        decoyJarPath,
        Collections.emptyList(),
        Collections.emptyList(),
        classDir.toPath(),
        ScanMode.DATA_FLOW,
        "test-worker");
    assertFalse(result.taintFlows().isEmpty(), "Should have detected at least one taint flow.");
    TaintFlow flow = result.taintFlows().get(0);
    assertTrue(flow.source().contains("onCommand"), "Taint source should be the onCommand method.");
    assertTrue(
        flow.sink().contains("java/lang/Runtime.exec"), "Taint sink should be Runtime.exec.");
  }
}
