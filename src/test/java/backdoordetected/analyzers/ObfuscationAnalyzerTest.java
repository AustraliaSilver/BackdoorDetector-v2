package backdoordetected.analyzers;

import static org.junit.jupiter.api.Assertions.*;

import backdoordetected.models.ObfuscationResult;
import backdoordetected.utils.ScanMode;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ObfuscationAnalyzerTest {

    @TempDir
    Path tempDir;

    @Test
    void testCleanCode() throws Exception {
        Path file = tempDir.resolve("Clean.java");
        Files.writeString(
                file,
                """
                        public class Clean {
                            public void doSomething() {
                                int variable = 1;
                                System.out.println(variable);
                            }
                        }
                        """);

        ObfuscationAnalyzer analyzer = new ObfuscationAnalyzer();
        ObfuscationResult result = (ObfuscationResult) analyzer.analyze(
                null,
                List.of(file),
                Collections.emptyList(),
                tempDir,
                ScanMode.BYTECODE,
                "test-worker");

        assertEquals(0, result.score());
        assertFalse(result.isHeavilyObfuscated());
        assertTrue(result.warnings().isEmpty());
    }

    @Test
    void testNameObfuscation() throws Exception {
        Path file = tempDir.resolve("Obfuscated.java");
        Files.writeString(
                file,
                """
                        public class A {
                            public void a() {
                                int a = 1;
                                int b = 2;
                                int c = 3;
                                String d = "test";
                            }
                            public void b() {
                                int e = 4;
                            }
                        }
                        """);

        ObfuscationAnalyzer analyzer = new ObfuscationAnalyzer();
        ObfuscationResult result = (ObfuscationResult) analyzer.analyze(
                null,
                List.of(file),
                Collections.emptyList(),
                tempDir,
                ScanMode.BYTECODE,
                "test-worker");

        assertTrue(result.score() > 0);
        assertTrue(result.warnings().stream().anyMatch(w -> w.contains("meaningless names")));
    }

    @Test
    void testHighComplexity() throws Exception {
        Path file = tempDir.resolve("Complex.java");
        StringBuilder sb = new StringBuilder();
        sb.append("public class Complex {\n");
        sb.append("    public void complexMethod() {\n");
        for (int i = 0; i < 25; i++) {
            sb.append("        if (true) { }\n");
        }
        sb.append("    }\n");
        sb.append("}\n");

        Files.writeString(file, sb.toString());

        ObfuscationAnalyzer analyzer = new ObfuscationAnalyzer();
        ObfuscationResult result = (ObfuscationResult) analyzer.analyze(
                null,
                List.of(file),
                Collections.emptyList(),
                tempDir,
                ScanMode.BYTECODE,
                "test-worker");

        assertTrue(result.score() > 0);
        assertTrue(result.warnings().stream().anyMatch(w -> w.contains("High cyclomatic complexity")));
    }

    @Test
    void testStringEncryption() throws Exception {
        Path file = tempDir.resolve("Encrypted.java");
        StringBuilder sb = new StringBuilder();
        sb.append("import java.util.Base64;\n");
        sb.append("public class Encrypted {\n");
        sb.append("    public void decode() {\n");
        for (int i = 0; i < 10; i++) {
            sb.append("        Base64.getDecoder().decode(\"test\");\n");
        }
        sb.append("    }\n");
        sb.append("}\n");

        Files.writeString(file, sb.toString());

        ObfuscationAnalyzer analyzer = new ObfuscationAnalyzer();
        ObfuscationResult result = (ObfuscationResult) analyzer.analyze(
                null,
                List.of(file),
                Collections.emptyList(),
                tempDir,
                ScanMode.BYTECODE,
                "test-worker");

        assertTrue(result.score() > 0);
        assertTrue(result.warnings().stream().anyMatch(w -> w.contains("Base64 decoding")));
    }

    @Test
    void testClassNameObfuscation() throws Exception {
        Path file = tempDir.resolve("A.java");
        Files.writeString(
                file,
                """
                        public class A {
                            public void a() {
                                int b = 1;
                            }
                        }
                        """);

        ObfuscationAnalyzer analyzer = new ObfuscationAnalyzer();
        ObfuscationResult result = (ObfuscationResult) analyzer.analyze(
                null,
                List.of(file),
                Collections.emptyList(),
                tempDir,
                ScanMode.BYTECODE,
                "test-worker");

        assertTrue(result.score() > 0);
        assertTrue(result.warnings().stream().anyMatch(w -> w.contains("meaningless names")));
    }

    @Test
    void testLogicalComplexity() throws Exception {
        Path file = tempDir.resolve("Logical.java");
        Files.writeString(
                file,
                """
                        public class Logical {
                            public void logic() {
                                if (true && true || false && true) {
                                    // Complexity should be 1+1+3=5
                                }
                            }
                        }
                        """);

        ObfuscationAnalyzer analyzer = new ObfuscationAnalyzer();
        StringBuilder sb = new StringBuilder();
        sb.append("public class LogicalComplex {\n");
        sb.append("    public void complex() {\n");
        sb.append("        if (");
        for (int i = 0; i < 25; i++) {
            sb.append("true && ");
        }
        sb.append("true) {}\n");
        sb.append("    }\n");
        sb.append("}\n");

        Files.writeString(file, sb.toString());

        ObfuscationResult result = (ObfuscationResult) analyzer.analyze(
                null,
                List.of(file),
                Collections.emptyList(),
                tempDir,
                ScanMode.BYTECODE,
                "test-worker");

        assertTrue(result.score() > 0);
        assertTrue(result.warnings().stream().anyMatch(w -> w.contains("High cyclomatic complexity")));
    }

    @Test
    void testSwitchCaseComplexity() throws Exception {
        Path file = tempDir.resolve("Switch.java");
        StringBuilder sb = new StringBuilder();
        sb.append("public class SwitchComplex {\n");
        sb.append("    public void switchMethod(int x) {\n");
        sb.append("        switch (x) {\n");
        for (int i = 0; i < 25; i++) {
            sb.append("            case " + i + ": break;\n");
        }
        sb.append("        }\n");
        sb.append("    }\n");
        sb.append("}\n");

        Files.writeString(file, sb.toString());

        ObfuscationAnalyzer analyzer = new ObfuscationAnalyzer();
        ObfuscationResult result = (ObfuscationResult) analyzer.analyze(
                null,
                List.of(file),
                Collections.emptyList(),
                tempDir,
                ScanMode.BYTECODE,
                "test-worker");

        assertTrue(result.score() > 0);
        assertTrue(result.warnings().stream().anyMatch(w -> w.contains("High cyclomatic complexity")));
    }

    @Test
    void testXorEncryption() throws Exception {
        Path file = tempDir.resolve("Xor.java");
        Files.writeString(
                file,
                """
                        public class Xor {
                            public void decrypt(byte[] data, byte key) {
                                for (int i = 0; i < data.length; i++) {
                                    data[i] = (byte) (data[i] ^ key);
                                }
                            }
                        }
                        """);

        ObfuscationAnalyzer analyzer = new ObfuscationAnalyzer();
        ObfuscationResult result = (ObfuscationResult) analyzer.analyze(
                null,
                List.of(file),
                Collections.emptyList(),
                tempDir,
                ScanMode.BYTECODE,
                "test-worker");

        assertTrue(result.score() > 0);
        assertTrue(result.warnings().stream().anyMatch(w -> w.contains("XOR operations")));
    }
}
