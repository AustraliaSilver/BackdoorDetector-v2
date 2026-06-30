package backdoordetected;

import backdoordetected.utils.SafeJavaParser;
import com.github.javaparser.ParseProblemException;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.StaticJavaParser;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

public class ParseErrorDiagnosticTest {

  @Test
  void findParseErrors() throws IOException {
    StaticJavaParser.getConfiguration().setLanguageLevel(ParserConfiguration.LanguageLevel.JAVA_18);
    Path cacheDir = Paths.get("decompile_cache");
    List<Path> allJavaFiles = new ArrayList<>();
    try (Stream<Path> walk = Files.walk(cacheDir)) {
      walk.filter(p -> p.toString().endsWith(".java")).forEach(allJavaFiles::add);
    }
    System.out.println("Total Java files: " + allJavaFiles.size());

    List<String> failedFiles = new ArrayList<>();
    int successCount = 0;
    for (Path file : allJavaFiles) {
      try {
        SafeJavaParser.parse(file);
        successCount++;
      } catch (IOException e) {
        String msg = e.getMessage();
        String snippet = msg != null ? msg.substring(0, Math.min(msg.length(), 300)).replace("\r\n", " | ").replace("\n", " | ") : "no message";
        failedFiles.add(file.getFileName().toString() + " -> " + snippet);
      } catch (RuntimeException e) {
        Throwable cause = e.getCause();
        String msg = cause != null ? cause.getMessage() : e.getMessage();
        String snippet = msg != null ? msg.substring(0, Math.min(msg.length(), 300)).replace("\r\n", " | ").replace("\n", " | ") : "no message";
        failedFiles.add(file.getFileName().toString() + " -> " + snippet);
      }
    }

    System.out.println("Successfully parsed: " + successCount);
    System.out.println("Failed to parse: " + failedFiles.size());
    for (String f : failedFiles) {
      System.out.println("  FAILED: " + f);
    }
  }
}
