package backdoordetected;

import com.microsoft.z3.*;
import sootup.core.jimple.basic.Immediate;
import sootup.core.jimple.basic.Local;
import sootup.core.jimple.basic.Value;
import sootup.core.jimple.common.expr.AbstractBinopExpr;
import sootup.core.jimple.common.stmt.JAssignStmt;
import sootup.core.jimple.common.stmt.JIfStmt;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.model.SootMethod;
import sootup.core.model.SootClass;
import sootup.core.signatures.MethodSignature;
import sootup.core.types.ClassType;
import sootup.core.types.VoidType;
import sootup.core.types.Type;
import sootup.core.views.View;
import sootup.java.bytecode.inputlocation.JavaClassPathAnalysisInputLocation;
import sootup.java.core.language.JavaLanguage;
import sootup.java.core.JavaProject;
import sootup.java.core.views.JavaView;

import java.nio.file.Path;
import java.util.*;
import java.util.logging.Logger;

public class SymbolicAnalyzer {

    private static final Logger logger = StandaloneLogger.getLogger();

    public BoolExpr createGoalFromConditionString(String variableName, String constantValue, Context ctx) {
        logger.info("Creating symbolic goal: " + variableName + " == \"" + constantValue + "\"");
        Expr<SeqSort<CharSort>> var = ctx.mkConst(variableName, ctx.getStringSort());
        Expr<SeqSort<CharSort>> val = ctx.mkString(constantValue);
        return ctx.mkEq(var, val);
    }
public void analyzeMethod(Path jarPath, String className, String methodSignature, BoolExpr backdoorCondition) {
    logger.info("🔬 Starting symbolic analysis for: " + className + "." + methodSignature);

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
        if (methodOpt.isPresent()) method = methodOpt.get();
        else {
            Optional<?> fallback = sootClass.getMethods().stream()
                    .filter(m -> ((SootMethod) m).getName().equals(methodName))
                    .findFirst();
            if (fallback.isPresent()) method = (SootMethod) fallback.get();
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

                if ("int".equals(tname) || "I".equals(tname)) symVar = ctx.mkIntConst("param" + i);
                else if ("boolean".equals(tname) || "Z".equals(tname)) symVar = ctx.mkBoolConst("param" + i);
                else if ("java.lang.String".equals(tname)) symVar = ctx.mkConst("param" + i, ctx.getStringSort());

                if (symVar != null) symbolicState.put(param, symVar);
            } catch (Throwable t) {
                logger.fine("Failed symbolic param " + i + ": " + t.getMessage());
            }
        }

        for (Stmt stmt : method.getBody().getStmts()) {
            if (stmt instanceof JAssignStmt assign) {
                Value left = assign.getLeftOp();
                Value right = assign.getRightOp();
                Expr<?> r = translateValue(right, symbolicState, ctx);
                if (r != null && left != null) symbolicState.put(left, r);
            } else if (stmt instanceof JIfStmt ifs) {
                Value condVal = ifs.getCondition();
                Expr<?> condExpr = translateValue(condVal, symbolicState, ctx);
                if (condExpr instanceof BoolExpr be) pathCondition = ctx.mkAnd(pathCondition, be);
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
        if (value == null) return null;
        if (state.containsKey(value)) return state.get(value);

        try {
            if (value instanceof Immediate) {
                String s = value.toString();
                if ("true".equals(s) || "false".equals(s)) return ctx.mkBool(Boolean.parseBoolean(s));
                try { return ctx.mkInt(Integer.parseInt(s)); } catch (NumberFormatException ignored) {}
                return ctx.mkConst(s, ctx.getStringSort());
            }

            if (value instanceof Local l && state.containsKey(l)) return state.get(l);

            if (value instanceof AbstractBinopExpr bin) {
                Expr<?> l = translateValue(bin.getOp1(), state, ctx);
                Expr<?> r = translateValue(bin.getOp2(), state, ctx);
                if (l == null || r == null) return null;

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
            StandaloneLogger.getLogger().fine("translateValue unhandled class " + value.getClass() + ": " + t.getMessage());
        }

        return null;
    }
}
