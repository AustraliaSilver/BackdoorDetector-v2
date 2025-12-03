package backdoordetected.utils;

import java.util.logging.ConsoleHandler;
import java.util.logging.Formatter;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

public class StandaloneLogger {
  private static final Logger logger = Logger.getLogger("BackdoorDetector");

  static {
    logger.setUseParentHandlers(false);
    ConsoleHandler handler = new ConsoleHandler();
    handler.setFormatter(
        new Formatter() {
          @Override
          public String format(LogRecord record) {
            return String.format(
                "[%s] [%s] %s%n",
                record.getLoggerName(), record.getLevel().getName(), record.getMessage());
          }
        });
    logger.addHandler(handler);
  }

  public static Logger getLogger() {
    return logger;
  }
}
