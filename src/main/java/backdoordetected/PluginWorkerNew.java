package backdoordetected;

import backdoordetected.models.PrioritizedFile;
import backdoordetected.services.PluginOrchestrator;
import backdoordetected.utils.ScanMode;
import backdoordetected.utils.StandaloneLogger;
import java.io.File;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

public class PluginWorkerNew implements Runnable {
  private static final Logger logger = StandaloneLogger.getLogger();
  private static final long QUEUE_POLL_TIMEOUT_SECONDS = 5;

  private final BlockingQueue<PrioritizedFile> queue;
  private final PluginOrchestrator orchestrator;
  private final String workerName;
  private final ScanMode scanMode;
  private final CountDownLatch latch;

  public PluginWorkerNew(
      BlockingQueue<PrioritizedFile> queue,
      PluginOrchestrator orchestrator,
      String workerName,
      ScanMode scanMode,
      CountDownLatch latch) {
    this.queue = queue;
    this.orchestrator = orchestrator;
    this.workerName = workerName;
    this.scanMode = scanMode;
    this.latch = latch;
  }

  @Override
  public void run() {
    logger.info("[" + workerName + "] Worker STARTED for mode: " + scanMode.name());

    try {
      while (true) {
        PrioritizedFile pFile = null;
        try {
          pFile = queue.poll(QUEUE_POLL_TIMEOUT_SECONDS, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
          Thread.currentThread().interrupt();
          logger.warning("[" + workerName + "] Interrupted while polling queue.");
          break;
        }

        if (pFile == null) {
          logger.info("[" + workerName + "] No more tasks in queue (timeout). Exiting loop.");
          break;
        }

        File plugin = pFile.file();
        logger.info("[" + workerName + "] Processing: " + plugin.getName());

        try {
          if (scanMode == ScanMode.AI_MODERN
              || scanMode == ScanMode.AI
              || scanMode == ScanMode.AI_BACKDOOR_FOCUS) {
            String result = orchestrator.scan(plugin.toPath(), scanMode, workerName);
            if (result != null && !result.isEmpty()) {
              System.out.println("\n╔═══════════════════════════════════════════════════════╗");
              System.out.println("║                   AI ANALYSIS RESULT                  ║");
              System.out.println("╠═══════════════════════════════════════════════════════╣");
              String[] lines = result.split("\n");
              for (String line : lines) {
                System.out.println("  " + line);
              }
              System.out.println("╚═══════════════════════════════════════════════════════╝\n");
            }
          } else {
            logger.warning(
                "["
                    + workerName
                    + "] Non-AI modes not yet migrated to new architecture. Using legacy implementation.");
          }
        } catch (Exception e) {
          logger.severe(
              "[" + workerName + "] Error processing " + plugin.getName() + ": " + e.getMessage());
          e.printStackTrace();
        }
      }
    } finally {
      if (latch != null) {
        latch.countDown();
      }
      logger.info("[" + workerName + "] Worker FINISHED");
    }
  }
}
