package backdoordetected.utils;

import com.github.javaparser.ParseProblemException;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public class SafeJavaParser {

  private static void ensureLanguageLevel() {
    StaticJavaParser.getConfiguration().setLanguageLevel(
        ParserConfiguration.LanguageLevel.JAVA_18);
  }

  public static CompilationUnit parse(Path file) throws IOException {
    return parse(file, true);
  }

  public static CompilationUnit parse(Path file, boolean retryWithPreprocessing)
      throws IOException {
    ensureLanguageLevel();
    try {
      return StaticJavaParser.parse(file);
    } catch (ParseProblemException e) {
      if (!retryWithPreprocessing) throw e;
      String source = Files.readString(file);
      String cleaned = SourcePreprocessor.preprocess(source);
      try {
        return StaticJavaParser.parse(cleaned);
      } catch (ParseProblemException e2) {
        throw new IOException(
            "Failed to parse " + file.getFileName() + " even after preprocessing: "
                + e2.getMessage(), e2);
      }
    }
  }

  public static CompilationUnit parse(String source) {
    ensureLanguageLevel();
    try {
      return StaticJavaParser.parse(source);
    } catch (ParseProblemException e) {
      String cleaned = SourcePreprocessor.preprocess(source);
      return StaticJavaParser.parse(cleaned);
    }
  }
}
