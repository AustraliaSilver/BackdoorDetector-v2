package backdoordetected.utils;

import backdoordetected.services.ConfigService;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

public class AnalysisThreadPool {
  private static final Logger logger = StandaloneLogger.getLogger();
  private static final int DEFAULT_POOL_SIZE = Runtime.getRuntime().availableProcessors();

  private static volatile ExecutorService sharedPool;
  private static volatile boolean enabled = true;

  public static synchronized ExecutorService getShared() {
    if (!enabled) {
      return Executors.newSingleThreadExecutor();
    }

    if (sharedPool == null || sharedPool.isShutdown()) {
      int poolSize = getConfiguredPoolSize();
      logger.info("Creating shared analysis thread pool with " + poolSize + " threads");

      sharedPool = Executors.newFixedThreadPool(
          poolSize,
          r -> {
            Thread t = new Thread(r);
            t.setName("AnalysisWorker-" + t.threadId());
            t.setDaemon(true);
            return t;
          });
    }
    return sharedPool;
  }

  private static int getConfiguredPoolSize() {
    try {
      ConfigService config = ConfigService.getInstance();
      int configuredSize = config.getIntProperty("global_thread_pool_size", 0);

      if (configuredSize > 0) {
        return Math.min(configuredSize, DEFAULT_POOL_SIZE * 2); 
      }
    } catch (Exception e) {
      logger.warning("Failed to get configured pool size: " + e.getMessage());
    }

    return DEFAULT_POOL_SIZE;
  }

  public static synchronized void setEnabled(boolean enable) {
    enabled = enable;
    if (!enable && sharedPool != null) {
      logger.info("Disabling shared thread pool");
      shutdown();
    }
  }

  public static boolean isEnabled() {
    try {
      ConfigService config = ConfigService.getInstance();
      return config.getBooleanProperty("enable_global_thread_pool", true);
    } catch (Exception e) {
      return true;
    }
  }

  public static synchronized void shutdown() {
    if (sharedPool != null && !sharedPool.isShutdown()) {
      logger.info("Shutting down shared analysis thread pool");
      sharedPool.shutdown();
      try {
        if (!sharedPool.awaitTermination(10, TimeUnit.SECONDS)) {
          logger.warning("Thread pool did not terminate in time, forcing shutdown");
          sharedPool.shutdownNow();
        }
      } catch (InterruptedException e) {
        logger.warning("Interrupted while waiting for thread pool shutdown");
        sharedPool.shutdownNow();
        Thread.currentThread().interrupt();
      }
      sharedPool = null;
    }
  }

  public static int getOptimalThreadCount(int taskCount) {
    if (!isEnabled()) {
      return 1;
    }

    int cores = Runtime.getRuntime().availableProcessors();
    int configuredMax = getConfiguredPoolSize();

    return Math.min(Math.min(cores, taskCount), configuredMax);
  }
}
