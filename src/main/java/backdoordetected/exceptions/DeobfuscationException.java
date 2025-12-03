package backdoordetected.exceptions;

public class DeobfuscationException extends AnalysisException {

  public DeobfuscationException(String message) {
    super(message);
  }

  public DeobfuscationException(String message, Throwable cause) {
    super(message, cause);
  }
}
