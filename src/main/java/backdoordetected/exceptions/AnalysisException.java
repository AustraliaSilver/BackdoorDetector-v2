package backdoordetected.exceptions;

public class AnalysisException extends Exception {

  public AnalysisException(String message) {
    super(message);
  }

  public AnalysisException(String message, Throwable cause) {
    super(message, cause);
  }

  public AnalysisException(Throwable cause) {
    super(cause);
  }
}
