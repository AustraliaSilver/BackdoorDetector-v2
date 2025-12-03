package backdoordetected.detection;

import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.MethodCallExpr;

public class SanitizerAnalyzer {

  public enum SanitizerStrength {
    NONE,
    WEAK,
    MEDIUM,
    STRONG
  }

  public static SanitizerStrength analyzeSanitizer(MethodCallExpr call) {
    String methodName = call.getNameAsString();

    if (methodName.equals("replace") || methodName.equals("replaceAll")) {
      return analyzeReplaceMethod(call);
    }

    if (methodName.equals("matches")) {
      return analyzeMatchesMethod(call);
    }

    if (isKnownStrongSanitizer(methodName)) {
      return SanitizerStrength.STRONG;
    }

    if (isKnownWeakSanitizer(methodName)) {
      return SanitizerStrength.WEAK;
    }

    return SanitizerStrength.NONE;
  }

  private static SanitizerStrength analyzeReplaceMethod(MethodCallExpr call) {
    if (call.getArguments().size() < 2) {
      return SanitizerStrength.NONE;
    }
    Expression pattern = call.getArgument(0);
    if (pattern.isStringLiteralExpr()) {
      String regex = pattern.asStringLiteralExpr().getValue();
      if (isStrongRegexPattern(regex)) {
        return SanitizerStrength.STRONG;
      }
      if (isWeakPattern(regex)) {
        return SanitizerStrength.WEAK;
      }
      return SanitizerStrength.MEDIUM;
    }

    return SanitizerStrength.NONE;
  }

  private static SanitizerStrength analyzeMatchesMethod(MethodCallExpr call) {
    if (call.getArguments().size() < 1) {
      return SanitizerStrength.NONE;
    }
    Expression pattern = call.getArgument(0);
    if (pattern.isStringLiteralExpr()) {
      String regex = pattern.asStringLiteralExpr().getValue();
      if (isStrongRegexPattern(regex)) {
        return SanitizerStrength.STRONG;
      }
    }
    return SanitizerStrength.NONE;
  }

  private static boolean isStrongRegexPattern(String regex) {
    if (regex.matches(".*\\[\\^[a-zA-Z0-9_\\-]+\\].*")) {
      return true;
    }
    if (regex.matches("\\[a-zA-Z0-9_\\-\\+\\*\\?\\{\\}\\|\\(\\)\\\\]+")) {
      return true;
    }
    if (regex.equals("[a-zA-Z0-9]+")
        || regex.equals("[a-z]+")
        || regex.equals("[A-Z]+")
        || regex.equals("[0-9]+")
        || regex.equals("[a-zA-Z0-9_-]+")
        || regex.equals("^[a-zA-Z0-9]+$")
        || regex.equals("^[a-z]+$")) {
      return true;
    }

    return false;
  }

  private static boolean isWeakPattern(String pattern) {
    if (pattern.length() == 1) {
      return true;
    }

    if (pattern.equals("'")
        || pattern.equals("\"")
        || pattern.equals(";")
        || pattern.equals("&")
        || pattern.equals("|")
        || pattern.equals("`")
        || pattern.equals("$")
        || pattern.equals("\\\\")
        || pattern.equals("/")) {
      return true;
    }

    if (pattern.equals("\\'") || pattern.equals("\\\"")) {
      return true;
    }

    return false;
  }

  private static boolean isKnownStrongSanitizer(String methodName) {
    return methodName.equals("sanitize")
        || methodName.equals("escapeHtml")
        || methodName.equals("escapeHtml4")
        || methodName.equals("escapeJava")
        || methodName.equals("escapeJson")
        || methodName.equals("escapeXml")
        || methodName.equals("escapeSql")
        || methodName.equals("escapeShellArg")
        || methodName.equals("stripTags")
        || methodName.equals("removeSpecialChars")
        || methodName.equals("alphanumericOnly");
  }

  private static boolean isKnownWeakSanitizer(String methodName) {
    return methodName.equals("trim")
        || methodName.equals("toLowerCase")
        || methodName.equals("toUpperCase")
        || methodName.equals("strip")
        || methodName.equals("stripLeading")
        || methodName.equals("stripTrailing");
  }

  public static String getStrengthDescription(SanitizerStrength strength) {
    return switch (strength) {
      case NONE -> "No sanitization";
      case WEAK -> "Weak sanitization (insufficient)";
      case MEDIUM -> "Medium sanitization (partial)";
      case STRONG -> "Strong sanitization (comprehensive)";
    };
  }
}
