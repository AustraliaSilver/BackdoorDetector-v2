package backdoordetected;

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

public class ParseErrorDiagnostic {
  public static void main(String[] args) throws IOException {
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
        StaticJavaParser.parse(file);
        successCount++;
      } catch (ParseProblemException e) {
        String msg = e.getMessage();
        String firstLine = msg != null ? msg.substring(0, Math.min(msg.length(), 200)) : "no message";
        failedFiles.add(file.getFileName() + " (" + file.getParent().getFileName() + "): " + firstLine);
        System.out.println("FAIL: " + file.getFileName() + " - " + firstLine);
      } catch (IOException e) {
        failedFiles.add(file.getFileName() + " (IO error): " + e.getMessage());
      }
    }
    System.out.println("\n=== RESULTS ===");
    System.out.println("Successfully parsed: " + successCount);
    System.out.println("Failed to parse: " + failedFiles.size());
    System.out.println("\nFailed files:");
    for (String f : failedFiles) {
      System.out.println("  " + f);
    }
  }
}
