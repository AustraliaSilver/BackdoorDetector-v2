package backdoordetected.analyzers;

import static org.junit.jupiter.api.Assertions.*;

import backdoordetected.models.DataFlowAnalysisResult;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class DataFlowAnalyzerTest {

    private DataFlowAnalyzer analyzer;
    @TempDir
    Path tempDir;

    @BeforeEach
    void setUp() {
        analyzer = new DataFlowAnalyzer();
    }

    private Path createSourceFile(Path root, String qualifiedName, String content)
            throws IOException {
        Path filePath = root.resolve("src/main/java").resolve(qualifiedName.replace('.', '/') + ".java");
        Files.createDirectories(filePath.getParent());
        Files.write(filePath, content.getBytes());
        return filePath;
    }

    private void createMockBukkitApi(Path root) throws IOException {
        createSourceFile(
                root, "org.bukkit.event.Event", "package org.bukkit.event; public class Event {}");
        createSourceFile(
                root, "org.bukkit.entity.Player", "package org.bukkit.entity; public interface Player {}");
        createSourceFile(
                root,
                "org.bukkit.event.player.PlayerEvent",
                "package org.bukkit.event.player; import org.bukkit.entity.Player; import org.bukkit.event.Event; public class PlayerEvent extends Event { public Player getPlayer() { return null; } }");
        createSourceFile(
                root,
                "org.bukkit.event.player.PlayerCommandPreprocessEvent",
                "package org.bukkit.event.player; public class PlayerCommandPreprocessEvent extends PlayerEvent { public String getMessage() { return \"/tainted command\"; } }");
    }

    @Test
    void detectsDirectTaintFlow() throws Exception {
        createMockBukkitApi(tempDir);
        String sourceCode = "package com.example;\n"
                + "import org.bukkit.event.player.PlayerCommandPreprocessEvent;\n"
                + "public class TaintedPlugin {\n"
                + "    public void onPlayerCommand(PlayerCommandPreprocessEvent event) {\n"
                + "        String command = event.getMessage();\n"
                + "        try {\n"
                + "            Runtime.getRuntime().exec(command);\n"
                + "        } catch (Exception e) {}\n"
                + "    }\n"
                + "}";
        Path javaFile = createSourceFile(tempDir, "com.example.TaintedPlugin", sourceCode);
        DataFlowAnalysisResult result = (DataFlowAnalysisResult) analyzer.analyze(
                Collections.singletonList(javaFile),
                tempDir.resolve("src/main/java"));
        assertFalse(result.getFileFindings().isEmpty(), "Should have findings");
        assertTrue(
                result.getFileFindings().values().stream()
                        .flatMap(List::stream)
                        .anyMatch(
                                s -> s.contains("CRITICAL DATA FLOW: Tainted data passed to dangerous sink 'exec'")),
                "Should detect taint flow to Runtime.exec");
    }

    @Test
    void ignoresSanitizedTaintFlow() throws Exception {
        createMockBukkitApi(tempDir);
        String sourceCode = "package com.example;\n"
                + "import org.bukkit.event.player.PlayerCommandPreprocessEvent;\n"
                + "public class SanitizedPlugin {\n"
                + "    public void onPlayerCommand(PlayerCommandPreprocessEvent event) {\n"
                + "        String command = event.getMessage();\n"
                + "        if (!command.matches(\"^[a-zA-Z0-9 ]*$\")) { return; }\n"
                + "        try {\n"
                + "            Runtime.getRuntime().exec(command);\n"
                + "        } catch (Exception e) {}\n"
                + "    }\n"
                + "}";
        Path javaFile = createSourceFile(tempDir, "com.example.SanitizedPlugin", sourceCode);

        DataFlowAnalysisResult result = (DataFlowAnalysisResult) analyzer.analyze(
                Collections.singletonList(javaFile),
                tempDir.resolve("src/main/java"));

        assertTrue(
                result.getFileFindings().isEmpty(),
                "Should not have findings for sanitized input. Findings: " + result.getFileFindings());
    }

    @Test
    void ignoresSemanticSafeTaintFlow() throws Exception {
        createMockBukkitApi(tempDir);
        String sourceCode = "package com.example;\n"
                + "import org.bukkit.event.player.PlayerCommandPreprocessEvent;\n"
                + "public class SemanticPlugin {\n"
                + "    public void onPlayerCommand(PlayerCommandPreprocessEvent event) {\n"
                + "        String command = event.getMessage();\n"
                + "        try {\n"
                + "            int pid = Integer.parseInt(command);\n"
                + "            // This should be considered semantically safe (INTEGER) and ignored\n"
                + "            Runtime.getRuntime().exec(\"kill \" + pid);\n"
                + "        } catch (Exception e) {}\n"
                + "    }\n"
                + "}";
        Path javaFile = createSourceFile(tempDir, "com.example.SemanticPlugin", sourceCode);
        DataFlowAnalysisResult result = (DataFlowAnalysisResult) analyzer.analyze(
                Collections.singletonList(javaFile),
                tempDir.resolve("src/main/java"));
        assertTrue(
                result.getFileFindings().isEmpty(),
                "Should not have findings for semantically safe input. Findings: "
                        + result.getFileFindings());
    }

    @Test
    void detectsConstantPropagationWithReflection() throws Exception {
        createMockBukkitApi(tempDir);
        String sourceCode = "package com.example;\n"
                + "public class ReflectionBackdoor {\n"
                + "    public void onPlayerCommand(String cmd) {\n"
                + "        try {\n"
                + "            String p1 = \"java.lang.Ru\";\n"
                + "            String p2 = \"ntime\";\n"
                + "            String className = p1 + p2;\n"
                + "            Class<?> clazz = Class.forName(className);\n"
                + "            Object runtime = clazz.getMethod(\"getRuntime\").invoke(null);\n"
                + "            clazz.getMethod(\"exec\", String.class).invoke(runtime, cmd);\n"
                + "        } catch (Exception e) {}\n"
                + "    }\n"
                + "}";
        Path javaFile = createSourceFile(tempDir, "com.example.ReflectionBackdoor", sourceCode);

        DataFlowAnalysisResult result = (DataFlowAnalysisResult) analyzer.analyze(
                Collections.singletonList(javaFile),
                tempDir.resolve("src/main/java"));
        assertFalse(result.getFileFindings().isEmpty(), "Should have findings for reflection backdoor");
    }
}
