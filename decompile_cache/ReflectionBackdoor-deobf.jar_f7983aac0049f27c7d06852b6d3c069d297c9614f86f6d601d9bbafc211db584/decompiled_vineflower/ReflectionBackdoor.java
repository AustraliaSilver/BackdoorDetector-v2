public class ReflectionBackdoor {
    public void run() throws Exception {
        Object var1 = Class.forName("java.lang.Runtime").getMethod("getRuntime").invoke(null);
        var1.getClass().getMethod("exec", String.class).invoke(var1, "calc.exe");
    }
}
