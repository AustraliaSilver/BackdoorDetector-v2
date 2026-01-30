public class DirectBackdoor {
    public void run() {
        try {
            Runtime.getRuntime().exec("calc.exe");
        } catch (Exception var2) {
        }
    }
}
