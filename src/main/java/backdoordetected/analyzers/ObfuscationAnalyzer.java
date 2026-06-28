package backdoordetected.analyzers;

import backdoordetected.models.ObfuscationResult;
import backdoordetected.models.PluginAnalysisResult;
import backdoordetected.services.PluginAnalyzer;
import backdoordetected.utils.ScanMode;
import backdoordetected.utils.SafeJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.AssignExpr;
import com.github.javaparser.ast.expr.BinaryExpr;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.stmt.DoStmt;
import com.github.javaparser.ast.stmt.ForStmt;
import com.github.javaparser.ast.stmt.IfStmt;
import com.github.javaparser.ast.stmt.SwitchEntry;
import com.github.javaparser.ast.stmt.WhileStmt;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;
import java.util.regex.Pattern;

public class ObfuscationAnalyzer implements PluginAnalyzer {

  private static final String ANALYZER_NAME = "ObfuscationAnalyzer";

  @Override
  public String getName() {
    return ANALYZER_NAME;
  }

  private static final Logger logger = backdoordetected.utils.StandaloneLogger.getLogger();

  private static final Pattern MEANINGLESS_NAME_PATTERN = Pattern.compile("^[a-zA-Z_]{1,2}\\d*$");
  private static final int COMPLEXITY_THRESHOLD = 20;
  private static final double NAME_OBFUSCATION_THRESHOLD = 0.5;

  @Override
  public PluginAnalysisResult analyze(
      Path pluginPath,
      List<Path> javaFiles,
      List<Path> classFiles,
      Path workingDir,
      ScanMode scanMode,
      String workerName)
      throws Exception {

    logger.info("[" + workerName + "] Running " + getName() + "...");
    boolean useParallel = backdoordetected.utils.AnalysisThreadPool.isEnabled() && javaFiles.size() > 10;

    ObfuscationResult result;
    if (useParallel) {
      result = analyzeParallel(javaFiles);
    } else {
      result = analyzeSequential(javaFiles);
    }
    boolean hasHighSeverity = result.isHeavilyObfuscated();
    boolean hasLowSeverity = !result.isHeavilyObfuscated() && !result.warnings().isEmpty();
    Map<String, List<String>> genericFindings = new HashMap<>();
    if (!result.warnings().isEmpty()) {
      genericFindings.put("warnings", new ArrayList<>(result.warnings()));
    }

    return new ObfuscationResult(
        getName(),
        genericFindings,
        hasHighSeverity,
        hasLowSeverity,
        result.score(),
        result.warnings(),
        result.isHeavilyObfuscated());
  }

  private ObfuscationResult analyzeParallel(List<Path> javaFiles) {
    java.util.concurrent.atomic.AtomicInteger totalIdentifiers = new java.util.concurrent.atomic.AtomicInteger(0);
    java.util.concurrent.atomic.AtomicInteger meaninglessIdentifiers = new java.util.concurrent.atomic.AtomicInteger(0);
    java.util.concurrent.atomic.AtomicInteger totalMethods = new java.util.concurrent.atomic.AtomicInteger(0);
    java.util.concurrent.atomic.AtomicInteger complexMethods = new java.util.concurrent.atomic.AtomicInteger(0);
    java.util.concurrent.atomic.AtomicInteger stringDecryptionCount = new java.util.concurrent.atomic.AtomicInteger(0);
    java.util.concurrent.atomic.AtomicInteger xorEncryptionCount = new java.util.concurrent.atomic.AtomicInteger(0);

    javaFiles.parallelStream()
        .forEach(
            file -> {
              try {
                CompilationUnit cu = SafeJavaParser.parse(file);
                List<ClassOrInterfaceDeclaration> classes = cu.findAll(ClassOrInterfaceDeclaration.class);
                for (ClassOrInterfaceDeclaration cls : classes) {
                  totalIdentifiers.incrementAndGet();
                  if (isMeaninglessName(cls.getNameAsString())) {
                    meaninglessIdentifiers.incrementAndGet();
                  }
                }

                List<VariableDeclarator> vars = cu.findAll(VariableDeclarator.class);
                for (VariableDeclarator var : vars) {
                  totalIdentifiers.incrementAndGet();
                  if (isMeaninglessName(var.getNameAsString())) {
                    meaninglessIdentifiers.incrementAndGet();
                  }
                }

                List<MethodDeclaration> methods = cu.findAll(MethodDeclaration.class);
                for (MethodDeclaration method : methods) {
                  totalIdentifiers.incrementAndGet();
                  if (isMeaninglessName(method.getNameAsString())) {
                    meaninglessIdentifiers.incrementAndGet();
                  }

                  int complexity = calculateCyclomaticComplexity(method);
                  totalMethods.incrementAndGet();
                  if (complexity > COMPLEXITY_THRESHOLD) {
                    complexMethods.incrementAndGet();
                  }
                }

                List<MethodCallExpr> methodCalls = cu.findAll(MethodCallExpr.class);
                for (MethodCallExpr call : methodCalls) {
                  if (call.getNameAsString().equals("decode")
                      && call.getScope().isPresent()
                      && call.getScope().get().toString().contains("Base64")) {
                    stringDecryptionCount.incrementAndGet();
                  }
                }

                List<Node> loops = new ArrayList<>();
                loops.addAll(cu.findAll(ForStmt.class));
                loops.addAll(cu.findAll(WhileStmt.class));
                loops.addAll(cu.findAll(DoStmt.class));

                for (Node loop : loops) {
                  List<BinaryExpr> xorOps = loop.findAll(
                      BinaryExpr.class, be -> be.getOperator() == BinaryExpr.Operator.XOR);
                  List<AssignExpr> xorAssigns = loop.findAll(
                      AssignExpr.class, ae -> ae.getOperator() == AssignExpr.Operator.XOR);

                  if (!xorOps.isEmpty() || !xorAssigns.isEmpty()) {
                    xorEncryptionCount.incrementAndGet();
                    break;
                  }
                }

              } catch (Exception e) {
                if (e instanceof com.github.javaparser.ParseProblemException) {
                  logger.warning(
                      "Failed to parse file "
                          + file.getFileName()
                          + ": Parse error (details suppressed)");
                } else {
                  logger.warning(
                      "Failed to parse file " + file.getFileName() + ": " + e.getMessage());
                }
              }
            });

    return calculateResult(
        totalIdentifiers.get(),
        meaninglessIdentifiers.get(),
        totalMethods.get(),
        complexMethods.get(),
        stringDecryptionCount.get(),
        xorEncryptionCount.get());
  }

  private ObfuscationResult analyzeSequential(List<Path> javaFiles) {
    int totalIdentifiers = 0;
    int meaninglessIdentifiers = 0;
    int totalMethods = 0;
    int complexMethods = 0;
    int stringDecryptionCount = 0;
    int xorEncryptionCount = 0;

    for (Path file : javaFiles) {
      try {
        CompilationUnit cu = SafeJavaParser.parse(file);
        List<ClassOrInterfaceDeclaration> classes = cu.findAll(ClassOrInterfaceDeclaration.class);
        for (ClassOrInterfaceDeclaration cls : classes) {
          totalIdentifiers++;
          if (isMeaninglessName(cls.getNameAsString())) {
            meaninglessIdentifiers++;
          }
        }

        List<VariableDeclarator> vars = cu.findAll(VariableDeclarator.class);
        for (VariableDeclarator var : vars) {
          totalIdentifiers++;
          if (isMeaninglessName(var.getNameAsString())) {
            meaninglessIdentifiers++;
          }
        }

        List<MethodDeclaration> methods = cu.findAll(MethodDeclaration.class);
        for (MethodDeclaration method : methods) {
          totalIdentifiers++;
          if (isMeaninglessName(method.getNameAsString())) {
            meaninglessIdentifiers++;
          }
          int complexity = calculateCyclomaticComplexity(method);
          totalMethods++;
          if (complexity > COMPLEXITY_THRESHOLD) {
            complexMethods++;
          }
        }

        List<MethodCallExpr> methodCalls = cu.findAll(MethodCallExpr.class);
        for (MethodCallExpr call : methodCalls) {
          if (call.getNameAsString().equals("decode")
              && call.getScope().isPresent()
              && call.getScope().get().toString().contains("Base64")) {
            stringDecryptionCount++;
          }
        }

        List<Node> loops = new ArrayList<>();
        loops.addAll(cu.findAll(ForStmt.class));
        loops.addAll(cu.findAll(WhileStmt.class));
        loops.addAll(cu.findAll(DoStmt.class));

        for (Node loop : loops) {
          List<BinaryExpr> xorOps = loop.findAll(BinaryExpr.class, be -> be.getOperator() == BinaryExpr.Operator.XOR);
          List<AssignExpr> xorAssigns = loop.findAll(AssignExpr.class,
              ae -> ae.getOperator() == AssignExpr.Operator.XOR);

          if (!xorOps.isEmpty() || !xorAssigns.isEmpty()) {
            xorEncryptionCount++;
          }
        }

      } catch (IOException e) {
      }
    }

    return calculateResult(
        totalIdentifiers,
        meaninglessIdentifiers,
        totalMethods,
        complexMethods,
        stringDecryptionCount,
        xorEncryptionCount);
  }

  private ObfuscationResult calculateResult(
      int totalIdentifiers,
      int meaninglessIdentifiers,
      int totalMethods,
      int complexMethods,
      int stringDecryptionCount,
      int xorEncryptionCount) {

    List<String> warnings = new ArrayList<>();

    int score = 0;

    double nameObfuscationRatio = totalIdentifiers > 0 ? (double) meaninglessIdentifiers / totalIdentifiers : 0;
    if (nameObfuscationRatio > NAME_OBFUSCATION_THRESHOLD) {
      score += 40;
      warnings.add(
          "High rate of meaningless names ("
              + String.format("%.2f", nameObfuscationRatio * 100)
              + "%)");
    }

    double complexMethodRatio = totalMethods > 0 ? (double) complexMethods / totalMethods : 0;
    if (complexMethodRatio > 0.1) {
      score += 30;
      warnings.add(
          "High cyclomatic complexity detected in "
              + String.format("%.2f", complexMethodRatio * 100)
              + "% of methods");
    }

    if (stringDecryptionCount > 5) {
      score += 30;
      warnings.add(
          "Frequent use of Base64 decoding detected (" + stringDecryptionCount + " instances)");
    }

    if (xorEncryptionCount > 0) {
      score += 40;
      warnings.add(
          "Detected XOR operations in loops (potential string decryption) - "
              + xorEncryptionCount
              + " instances");
    }
    boolean isHeavilyObfuscated = score >= 50;
    Map<String, List<String>> genericFindings = new HashMap<>();
    if (!warnings.isEmpty()) {
      genericFindings.put("warnings", new ArrayList<>(warnings));
    }

    return new ObfuscationResult(
        ANALYZER_NAME,
        genericFindings,
        isHeavilyObfuscated,
        score > 0 && !isHeavilyObfuscated,
        score,
        warnings,
        isHeavilyObfuscated);
  }

  private boolean isMeaninglessName(String name) {
    return MEANINGLESS_NAME_PATTERN.matcher(name).matches();
  }

  private int calculateCyclomaticComplexity(MethodDeclaration method) {
    int complexity = 1;
    complexity += method.findAll(IfStmt.class).size();
    complexity += method.findAll(WhileStmt.class).size();
    complexity += method.findAll(ForStmt.class).size();
    complexity += method.findAll(DoStmt.class).size();
    complexity += method.findAll(SwitchEntry.class).size();
    complexity += method
        .findAll(
            BinaryExpr.class,
            expr -> expr.getOperator() == BinaryExpr.Operator.AND
                || expr.getOperator() == BinaryExpr.Operator.OR)
        .size();

    return complexity;
  }
}
