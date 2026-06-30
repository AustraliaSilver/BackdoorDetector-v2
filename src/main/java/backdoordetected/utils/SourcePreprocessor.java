package backdoordetected.utils;

import java.util.regex.Pattern;

public class SourcePreprocessor {

  private static final Pattern BOOTSTRAP_ARG_PATTERN =
      Pattern.compile("<\"[vw]\">(?=\\()");
  private static final Pattern NAMELESS_ENCLOSURE_PATTERN =
      Pattern.compile("<VAR_NAMELESS_ENCLOSURE>");
  private static final Pattern UNREPRESENTABLE_PATTERN =
      Pattern.compile("<unrepresentable>", Pattern.LITERAL);
  private static final Pattern MISSING_CTOR_PARENS_PATTERN =
      Pattern.compile("new\\s+([a-zA-Z_][a-zA-Z0-9_.]*)\\s*(;|\\s*\\{)");
  private static final Pattern DO_METHOD_PATTERN =
      Pattern.compile("\\.do\\s*\\(");
  private static final Pattern CAST_BEFORE_INVOKE_PATTERN =
      Pattern.compile("\\((\\w+(?:\\.\\w+)*)\\)(\\w+)\\.invoke\\(");
  private static final Pattern REQUIRE_NONNULL_BEFORE_SUPER_PATTERN =
      Pattern.compile("Objects\\.requireNonNull\\([^;]+\\);\\s*[\\r\\n]+\\s*super\\(");
  private static final Pattern INIT_METHOD_PATTERN =
      Pattern.compile("\\.(\\s*/\\*[^*]*\\*/\\s*)?<init>\\s*\\(");

  private static final String UNREPRESENTABLE_REPLACEMENT = "SwitchMapAccess";
  private static final String MISSING_CTOR_PARENS_REPLACEMENT = "new $1()$2";
  private static final String DO_METHOD_REPLACEMENT = ".callDo(";
  private static final String CAST_BEFORE_INVOKE_REPLACEMENT = "$2.invoke(";
  private static final String INIT_METHOD_REPLACEMENT = ".constructorInit(";

  public static String preprocess(String source) {
    if (source == null || source.isEmpty()) return source;

    String result = source;

    result = BOOTSTRAP_ARG_PATTERN.matcher(result).replaceAll("");
    result = NAMELESS_ENCLOSURE_PATTERN.matcher(result).replaceAll("null");
    result = UNREPRESENTABLE_PATTERN.matcher(result).replaceAll(UNREPRESENTABLE_REPLACEMENT);
    result = MISSING_CTOR_PARENS_PATTERN.matcher(result).replaceAll(MISSING_CTOR_PARENS_REPLACEMENT);
    result = DO_METHOD_PATTERN.matcher(result).replaceAll(DO_METHOD_REPLACEMENT);
    result = CAST_BEFORE_INVOKE_PATTERN.matcher(result).replaceAll(CAST_BEFORE_INVOKE_REPLACEMENT);
    result = REQUIRE_NONNULL_BEFORE_SUPER_PATTERN.matcher(result).replaceAll("super(");
    result = INIT_METHOD_PATTERN.matcher(result).replaceAll(INIT_METHOD_REPLACEMENT);
    return result;
  }
}
