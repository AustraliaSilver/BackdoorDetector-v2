package backdoordetected.exceptions;

public class AIAnalysisException extends AnalysisException {

    public AIAnalysisException(String message) {
        super(message);
    }

    public AIAnalysisException(String message, Throwable cause) {
        super(message, cause);
    }
}
