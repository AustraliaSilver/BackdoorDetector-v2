package backdoordetected.exceptions;

public class DecompilationException extends AnalysisException {

  public DecompilationException(String message) {
    super(message);
  }

  public DecompilationException(String message, Throwable cause) {
    super(message, cause);
  }
}
