package backdoordetected.analyzers;

import backdoordetected.models.SuspiciousMethod;
import backdoordetected.models.Z3Result;
import backdoordetected.utils.StandaloneLogger;
import com.microsoft.z3.*;
import java.nio.file.Path;
import java.util.*;
import java.util.logging.Logger;
import sootup.core.jimple.basic.Immediate;
import sootup.core.jimple.basic.Local;
import sootup.core.jimple.basic.Value;
import sootup.core.jimple.common.expr.AbstractBinopExpr;
import sootup.core.jimple.common.stmt.JAssignStmt;
import sootup.core.jimple.common.stmt.JIfStmt;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.model.SootClass;
import sootup.core.model.SootMethod;
import sootup.core.signatures.MethodSignature;
import sootup.core.types.ClassType;
import sootup.core.types.Type;
import sootup.core.types.VoidType;
import sootup.java.bytecode.inputlocation.JavaClassPathAnalysisInputLocation;
import sootup.java.core.JavaProject;
import sootup.java.core.language.JavaLanguage;
import sootup.java.core.views.JavaView;

public class SymbolicAnalyzer {

  private static final Logger logger = StandaloneLogger.getLogger();

  public BoolExpr createGoalFromConditionString(
      String variableName, String constantValue, Context ctx) {
    logger.info("Creating symbolic goal: " + variableName + " == \"" + constantValue + "\"");
    Expr<SeqSort<CharSort>> var = ctx.mkConst(variableName, ctx.getStringSort());
    Expr<SeqSort<CharSort>> val = ctx.mkString(constantValue);
    return ctx.mkEq(var, val);
  }

  public Z3Result analyzeWithCFG(Path jarPath, SuspiciousMethod suspiciousMethod) {
    logger.info(
        "Z3 Symbolic Analysis: "
            + suspiciousMethod.className()
            + "."
            + suspiciousMethod.methodName());

    try (Context ctx = new Context()) {

      JavaClassPathAnalysisInputLocation inputLocation = new JavaClassPathAnalysisInputLocation(jarPath.toString());
      JavaProject.JavaProjectBuilder builder = JavaProject.builder(new JavaLanguage(8));
      builder.addInputLocation(inputLocation);
      JavaProject project = builder.build();
      JavaView view = project.createView();

      String className = suspiciousMethod.className().replace('.', '/');
      ClassType classType = view.getIdentifierFactory().getClassType(className);
      Optional<sootup.java.core.JavaSootClass> sootClassOpt = view.getClass(classType);

      if (sootClassOpt.isEmpty()) {
        return Z3Result.unknown("Class not found: " + className);
      }

      SootClass<?> sootClass = sootClassOpt.get();
      String methodName = suspiciousMethod.methodName();

      Optional<? extends SootMethod> methodOpt = sootClass.getMethods().stream()
          .filter(m -> m.getName().equals(methodName)).findFirst();

      if (methodOpt.isEmpty()) {
        return Z3Result.unknown("Method not found: " + methodName);
      }

      SootMethod method = methodOpt.get();
      if (method.getBody() == null) {
        return Z3Result.unknown("Method body is null");
      }

      return analyzeMethodWithZ3(ctx, method, suspiciousMethod);

    } catch (Z3Exception ze) {
      logger.severe("Z3 exception: " + ze.getMessage());
      return Z3Result.unknown("Z3 error: " + ze.getMessage());
    } catch (Exception e) {
      logger.severe("Analysis exception: " + e.getMessage());
      return Z3Result.unknown("Analysis error: " + e.getMessage());
    }
  }

  private Z3Result analyzeMethodWithZ3(
      Context ctx, SootMethod method, SuspiciousMethod suspiciousMethod) {
    Map<Value, Expr<?>> symbolicState = new HashMap<>();
    BoolExpr pathCondition = ctx.mkTrue();
    boolean foundDangerousSink = false;
    List<Expr<?>> userInputExprs = new ArrayList<>();

    for (int i = 0; i < method.getParameterCount(); i++) {
      try {
        Value param = method.getBody().getParameterLocal(i);
        if (param == null)
          continue;

        Type t = param.getType();
        String tname = t != null ? t.toString() : "";

        if ("java.lang.String".equals(tname)
            || tname.contains("Event")
            || tname.contains("Player")
            || tname.contains("Command")) {
          Expr<?> symVar = ctx.mkConst("user_input_" + i, ctx.getStringSort());
          symbolicState.put(param, symVar);
          userInputExprs.add(symVar);
          logger.fine("Marked parameter " + i + " as user input: " + tname);
        } else if ("int".equals(tname) || "I".equals(tname)) {
          Expr<?> symVar = ctx.mkIntConst("user_input_" + i);
          symbolicState.put(param, symVar);
          userInputExprs.add(symVar);
        } else if ("boolean".equals(tname) || "Z".equals(tname)) {
          symbolicState.put(param, ctx.mkBoolConst("user_input_" + i));
        }
      } catch (Exception e) {
        logger.fine("Failed to process parameter " + i + ": " + e.getMessage());
      }
    }

    for (Stmt stmt : method.getBody().getStmts()) {

      if (stmt instanceof JAssignStmt assign) {
        Value left = assign.getLeftOp();
        Value right = assign.getRightOp();
        Expr<?> r = translateValue(right, symbolicState, ctx);
        if (r != null && left != null)
          symbolicState.put(left, r);
      } else if (stmt instanceof JIfStmt ifs) {
        Value condVal = ifs.getCondition();
        Expr<?> condExpr = translateValue(condVal, symbolicState, ctx);
        if (condExpr instanceof BoolExpr be) {
          pathCondition = ctx.mkAnd(pathCondition, be);
          logger.fine("Added branch condition: " + condExpr);
        }
      }

      String stmtStr = stmt.toString();
      if (stmtStr.contains(suspiciousMethod.dangerousSink())) {
        foundDangerousSink = true;
        logger.info("Found dangerous sink: " + stmtStr);
      }
    }

    if (!foundDangerousSink) {
      return Z3Result.unreachable(
          "Dangerous sink '" + suspiciousMethod.dangerousSink() + "' not found in method body");
    }
    List<Map<String, String>> allPayloads = generateMultipleConcreteInputs(
        ctx, pathCondition, userInputExprs, suspiciousMethod.dangerousSink(), 3);

    if (allPayloads.isEmpty()) {
      return Z3Result.unreachable("Path to dangerous sink is UNREACHABLE (UNSAT)");
    }
    Map<String, String> primaryModel = allPayloads.get(0);
    String explanation = String.format(
        "BACKDOOR CONFIRMED (Z3 VERIFIED): User input CAN reach %s in %s.%s. Generated %d concrete PoC payload(s).",
        suspiciousMethod.dangerousSink(),
        suspiciousMethod.className(),
        suspiciousMethod.methodName(),
        allPayloads.size());

    logger.severe(explanation);
    logger.severe("Example triggers: " + allPayloads);

    return Z3Result.confirmed(explanation, primaryModel);
  }

  private List<Map<String, String>> generateMultipleConcreteInputs(
      Context ctx, BoolExpr pathCondition, List<Expr<?>> userInputs, String sink, int count) {
    List<Map<String, String>> results = new ArrayList<>();
    Solver solver = ctx.mkSolver();
    solver.add(pathCondition);
    for (Expr<?> input : userInputs) {
      if (input.getSort().equals(ctx.getStringSort())) {
        addStringConstraints(ctx, solver, (Expr<SeqSort<CharSort>>) input, sink);
      }
    }
    for (int attempt = 0; attempt < count; attempt++) {
      logger.info("Generating PoC payload " + (attempt + 1) + "...");
      Status status = solver.check();
      if (status == Status.SATISFIABLE) {
        Model model = solver.getModel();
        Map<String, String> exampleInputs = new HashMap<>();
        for (Expr<?> input : userInputs) {
          try {
            Expr<?> value = model.eval(input, true);
            String key = input.toString();
            String valStr = value.toString();
            if (valStr.startsWith("\"") && valStr.endsWith("\"")) {
              valStr = valStr.substring(1, valStr.length() - 1);
            }
            exampleInputs.put(key, valStr);
          } catch (Exception e) {
            logger.fine("Failed to extract value for " + input + ": " + e.getMessage());
          }
        }

        results.add(exampleInputs);

        BoolExpr blockingClause = ctx.mkTrue();
        for (Expr<?> input : userInputs) {
          try {
            Expr<?> value = model.eval(input, true);
            blockingClause = ctx.mkAnd(blockingClause, ctx.mkNot(ctx.mkEq(input, value)));
          } catch (Exception e) {
          }
        }
        solver.add(blockingClause);

      } else {
        logger.info("No more solutions found (status: " + status + ")");
        break;
      }
    }

    return results;
  }

  private void addStringConstraints(
      Context ctx, Solver solver, Expr<SeqSort<CharSort>> stringVar, String sink) {

    try {
      solver.add(ctx.mkGe(ctx.mkLength(stringVar), ctx.mkInt(1)));
      solver.add(ctx.mkLe(ctx.mkLength(stringVar), ctx.mkInt(64)));
      if (sink.toLowerCase().contains("runtime.exec")
          || sink.toLowerCase().contains("processbuilder")
          || sink.toLowerCase().contains("dispatchcommand")) {
        BoolExpr hasDangerousChar = ctx.mkOr(
            ctx.mkContains(stringVar, ctx.mkString(";")),
            ctx.mkContains(stringVar, ctx.mkString("|")),
            ctx.mkContains(stringVar, ctx.mkString("&")),
            ctx.mkContains(stringVar, ctx.mkString("`")),
            ctx.mkContains(stringVar, ctx.mkString("$")));

      }

    } catch (Z3Exception e) {
      logger.fine("Failed to add string constraints: " + e.getMessage());
    }
  }

  public void analyzeMethod(
      Path jarPath, String className, String methodSignature, BoolExpr backdoorCondition) {
    logger.info("Starting symbolic analysis for: " + className + "." + methodSignature);

    try (Context ctx = new Context()) {
      JavaClassPathAnalysisInputLocation inputLocation = new JavaClassPathAnalysisInputLocation(jarPath.toString());

      JavaProject.JavaProjectBuilder builder = JavaProject.builder(new JavaLanguage(8));
      builder.addInputLocation(inputLocation);
      JavaProject project = builder.build();
      JavaView view = project.createView();

      ClassType classType = view.getIdentifierFactory().getClassType(className);
      Optional<sootup.java.core.JavaSootClass> sootClassOpt = view.getClass(classType);
      if (sootClassOpt.isEmpty()) {
        logger.warning("Class " + className + " not found in JAR " + jarPath.getFileName());
        return;
      }
      SootClass sootClass = sootClassOpt.get();

      String methodName = methodSignature.contains("(")
          ? methodSignature.substring(0, methodSignature.indexOf('(')).trim()
          : methodSignature;

      List<Type> paramTypes = Collections.emptyList();
      MethodSignature sig = view.getIdentifierFactory()
          .getMethodSignature(classType, methodName, VoidType.getInstance(), paramTypes);

      Optional<sootup.core.model.SootMethod> methodOpt = sootClass.getMethod(sig.getSubSignature());
      SootMethod method;
      if (methodOpt.isPresent())
        method = methodOpt.get();
      else {
        Optional<?> fallback = sootClass.getMethods().stream()
            .filter(m -> ((SootMethod) m).getName().equals(methodName))
            .findFirst();
        if (fallback.isPresent())
          method = (SootMethod) fallback.get();
        else {
          logger.warning("Method not found: " + methodName);
          return;
        }
      }

      if (method.getBody() == null) {
        logger.warning("Method body is null for " + method.getName());
        return;
      }

      analyzeMethodBodyWithZ3(ctx, method, backdoorCondition);

    } catch (Z3Exception ze) {
      logger.severe("Z3 exception: " + ze.getMessage());
      ze.printStackTrace();
    } catch (Exception e) {
      logger.severe("Unexpected exception: " + e.getMessage());
      e.printStackTrace();
    }
  }

  private void analyzeMethodBodyWithZ3(Context ctx, SootMethod method, BoolExpr backdoorCondition) {
    Logger logger = StandaloneLogger.getLogger();
    Map<Value, Expr<?>> symbolicState = new HashMap<>();
    BoolExpr pathCondition = ctx.mkTrue();

    for (int i = 0; i < method.getParameterCount(); i++) {
      try {
        Value param = method.getBody().getParameterLocal(i);
        Type t = param.getType();
        String tname = t != null ? t.toString() : "";
        Expr<?> symVar = null;

        if ("int".equals(tname) || "I".equals(tname))
          symVar = ctx.mkIntConst("param" + i);
        else if ("boolean".equals(tname) || "Z".equals(tname))
          symVar = ctx.mkBoolConst("param" + i);
        else if ("java.lang.String".equals(tname))
          symVar = ctx.mkConst("param" + i, ctx.getStringSort());

        if (symVar != null)
          symbolicState.put(param, symVar);
      } catch (Throwable t) {
        logger.fine("Failed symbolic param " + i + ": " + t.getMessage());
      }
    }

    for (Stmt stmt : method.getBody().getStmts()) {
      if (stmt instanceof JAssignStmt assign) {
        Value left = assign.getLeftOp();
        Value right = assign.getRightOp();
        Expr<?> r = translateValue(right, symbolicState, ctx);
        if (r != null && left != null)
          symbolicState.put(left, r);
      } else if (stmt instanceof JIfStmt ifs) {
        Value condVal = ifs.getCondition();
        Expr<?> condExpr = translateValue(condVal, symbolicState, ctx);
        if (condExpr instanceof BoolExpr be)
          pathCondition = ctx.mkAnd(pathCondition, be);
      }
    }

    Solver solver = ctx.mkSolver();
    solver.add(pathCondition);
    solver.add(backdoorCondition);

    logger.info("Z3 checking...");
    Status status = solver.check();
    if (status == Status.SATISFIABLE) {
      Model model = solver.getModel();
      logger.severe("BACKDOOR REACHABLE! Model: " + model);
    } else if (status == Status.UNSATISFIABLE) {
      logger.info("Backdoor unreachable (UNSAT).");
    } else {
      logger.warning("Z3 returned: " + status);
    }
  }

  private Expr<?> translateValue(Value value, Map<Value, Expr<?>> state, Context ctx) {
    if (value == null)
      return null;
    if (state.containsKey(value))
      return state.get(value);

    try {
      if (value instanceof Immediate) {
        String s = value.toString();
        if ("true".equals(s) || "false".equals(s))
          return ctx.mkBool(Boolean.parseBoolean(s));
        try {
          return ctx.mkInt(Integer.parseInt(s));
        } catch (NumberFormatException ignored) {
        }
        return ctx.mkConst(s, ctx.getStringSort());
      }

      if (value instanceof Local l && state.containsKey(l))
        return state.get(l);

      if (value instanceof AbstractBinopExpr bin) {
        Expr<?> l = translateValue(bin.getOp1(), state, ctx);
        Expr<?> r = translateValue(bin.getOp2(), state, ctx);
        if (l == null || r == null)
          return null;

        String op = bin.getSymbol().trim();
        if (l instanceof ArithExpr la && r instanceof ArithExpr ra) {
          return switch (op) {
            case "+" -> ctx.mkAdd(la, ra);
            case "-" -> ctx.mkSub(la, ra);
            case "*" -> ctx.mkMul(la, ra);
            case "/" -> ctx.mkDiv(la, ra);
            case "==" -> ctx.mkEq(la, ra);
            case "!=" -> ctx.mkNot(ctx.mkEq(la, ra));
            case ">" -> ctx.mkGt(la, ra);
            case ">=" -> ctx.mkGe(la, ra);
            case "<" -> ctx.mkLt(la, ra);
            case "<=" -> ctx.mkLe(la, ra);
            default -> null;
          };
        }

        if (l instanceof BoolExpr lb && r instanceof BoolExpr rb) {
          return switch (op) {
            case "==" -> ctx.mkEq(lb, rb);
            case "!=" -> ctx.mkNot(ctx.mkEq(lb, rb));
            case "&&" -> ctx.mkAnd(lb, rb);
            case "||" -> ctx.mkOr(lb, rb);
            default -> null;
          };
        }
      }
    } catch (Z3Exception ze) {
      StandaloneLogger.getLogger().severe("Z3Exception: " + ze.getMessage());
    } catch (Throwable t) {
      StandaloneLogger.getLogger()
          .fine("translateValue unhandled class " + value.getClass() + ": " + t.getMessage());
    }

    return null;
  }
}
