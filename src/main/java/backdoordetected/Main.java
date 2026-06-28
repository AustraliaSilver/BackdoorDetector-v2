package backdoordetected;

import backdoordetected.models.PrioritizedFile;
import backdoordetected.services.*;
import backdoordetected.utils.ScanMode;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.StaticJavaParser;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.logging.ConsoleHandler;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

public class Main {
  private static final Logger logger = Logger.getLogger(Main.class.getName());
  private static final String VERSION = "1.1.1";

  public static void main(String[] args) {
    setupLogger();
    printBanner();
    StaticJavaParser.getConfiguration().setLanguageLevel(ParserConfiguration.LanguageLevel.JAVA_18);

    ConfigService config = ConfigService.getInstance();

    if (args.length < 2 || !args[0].equalsIgnoreCase("scan")) {
      printUsage();
      return;
    }

    String pluginPath = args[1];
    ScanMode mode = ScanMode.AI_MODERN;

    if (args.length > 2) {
      try {
        mode = ScanMode.valueOf(args[2].toUpperCase());
      } catch (IllegalArgumentException e) {
        logger.severe("Invalid scan mode: " + args[2]);
        ScanMode.printAllModes();
        System.out.println("TIP: Use one of the modes listed above");
        return;
      }
    }

    if (mode.requiresApiKey()) {
      boolean hasApiKey = isApiKeyConfigured(config);
      boolean hasBackend = "backend".equalsIgnoreCase(config.getProperty("primary_ai", "backend"))
          || (config.getProperty("ai_backend_url") != null
              && !config.getProperty("ai_backend_url").isEmpty()
              && !config.getProperty("ai_backend_url").startsWith("YOUR_"));
      if (!hasApiKey && !hasBackend) {
        logger.severe("Scan mode " + mode.name() + " requires a valid Gemini API key or ai_backend_url.");
        logger.severe("   Please configure API key or backend URL in config.properties");
        logger.info("\nAlternative: Use non-AI modes like DATA_FLOW or BYTECODE");
        return;
      }
    }

    File targetPath = new File(pluginPath);
    if (!targetPath.exists()) {
      logger.severe("Path not found: " + pluginPath);
      return;
    }

    List<File> jarFiles = new ArrayList<>();

    if (targetPath.isDirectory()) {
      logger.info("Scanning directory: " + targetPath.getAbsolutePath());
      File[] files = targetPath.listFiles((dir, name) -> name.toLowerCase().endsWith(".jar"));
      if (files == null || files.length == 0) {
        logger.severe("No .jar files found in directory: " + pluginPath);
        return;
      }
      for (File file : files) {
        jarFiles.add(file);
      }
      logger.info("Found " + jarFiles.size() + " JAR file(s) to scan");
    } else if (targetPath.isFile()) {
      if (!targetPath.getName().toLowerCase().endsWith(".jar")) {
        logger.severe("Invalid file type. Expected .jar file, got: " + targetPath.getName());
        return;
      }
      jarFiles.add(targetPath);
    } else {
      logger.severe("Invalid path: " + pluginPath);
      return;
    }

    printScanHeader(jarFiles, mode);
    executeScan(jarFiles, mode, config);
  }

  private static void printBanner() {
    System.out.println("\n╔═══════════════════════════════════════════════════════╗");
    System.out.println("║   Minecraft Plugin Backdoor Detector " + VERSION + " ║");
    System.out.println("║           Advanced Security Analysis Tool             ║");
    System.out.println("╚═══════════════════════════════════════════════════════╝\n");
  }

  private static void printUsage() {
    System.out.println("USAGE:");
    System.out.println("  java -jar BackdoorDetect.jar scan <path> [mode]");
    System.out.println("  <path> can be a single .jar file or a directory containing .jar files\n");
    System.out.println("EXAMPLES:");
    System.out.println("  java -jar BackdoorDetect.jar scan plugin.jar");
    System.out.println("  java -jar BackdoorDetect.jar scan plugin.jar AI_MODERN");
    System.out.println("  java -jar BackdoorDetect.jar scan /path/to/plugins/ AI_MODERN\n");
    ScanMode.printAllModes();
    System.out.println("RECOMMENDATIONS:");
    System.out.println("  • Best accuracy: AI_MODERN (requires API key)");
    System.out.println("  • Scan entire plugin directory for batch analysis\n");
  }

  private static void printScanHeader(List<File> jarFiles, ScanMode mode) {
    System.out.println("╔═══════════════════════════════════════════════════════╗");
    if (jarFiles.size() == 1) {
      System.out.println("  Plugin: " + jarFiles.get(0).getName());
    } else {
      System.out.println("  Batch Scan: " + jarFiles.size() + " plugin(s)");
    }
    System.out.println("  Mode: " + mode.name());
    System.out.println("  Description: " + mode.getDescription());
    System.out.println("╚═══════════════════════════════════════════════════════╝\n");
  }

  private static void executeScan(List<File> jarFiles, ScanMode mode, ConfigService config) {
    BlockingQueue<PrioritizedFile> queue = new LinkedBlockingQueue<>();
    for (File jarFile : jarFiles) {
      queue.offer(new PrioritizedFile(jarFile, 0));
    }

    boolean allowParallelAi = config.getBooleanProperty("ai_parallel_scanning", false);
    String scanTarget = jarFiles.size() == 1 ? jarFiles.get(0).getName() : jarFiles.size() + " plugins";

    if (mode.requiresApiKey() && !allowParallelAi) {
      logger.info("AI scan mode detected. Running in sequential mode to avoid rate limits.");
      logger.info(
          "To enable parallel AI scans, set 'ai_parallel_scanning=true' in config.properties.");
      startSequentialScan(queue, mode, scanTarget);
    } else {
      startParallelScan(queue, mode, scanTarget);
    }
  }

  private static void setupLogger() {
    logger.setUseParentHandlers(false);
    ConsoleHandler handler = new ConsoleHandler();
    handler.setFormatter(new SimpleFormatter());
    logger.addHandler(handler);
  }

  private static boolean isApiKeyConfigured(ConfigService config) {
    String apiKey = config.getProperty("gemini_api_key");
    return apiKey != null && !apiKey.isEmpty() && !apiKey.startsWith("YOUR_");
  }

  private static void startSequentialScan(
      BlockingQueue<PrioritizedFile> queue, ScanMode mode, String pluginName) {
    CountDownLatch latch = new CountDownLatch(1);
    ExecutorService executor = Executors.newFixedThreadPool(1);
    PluginOrchestrator orchestrator = ServiceFactory.createPluginOrchestrator(mode);

    executor.submit(new PluginWorkerNew(queue, orchestrator, "SCANNER", mode, latch));

    try {
      latch.await();
      printScanComplete(pluginName);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      logger.severe("Scan interrupted");
    } finally {
      executor.shutdownNow();
    }
  }

  private static void startParallelScan(
      BlockingQueue<PrioritizedFile> queue, ScanMode mode, String pluginName) {
    int numThreads = Math.max(1, Runtime.getRuntime().availableProcessors() / 2);
    logger.info("Starting parallel scan with " + numThreads + " worker threads.");

    ExecutorService executor = Executors.newFixedThreadPool(numThreads);
    CountDownLatch latch = new CountDownLatch(numThreads);
    PluginOrchestrator orchestrator = ServiceFactory.createPluginOrchestrator(mode);

    for (int i = 0; i < numThreads; i++) {
      executor.submit(new PluginWorkerNew(queue, orchestrator, "WORKER-" + (i + 1), mode, latch));
    }

    try {
      latch.await();
      printScanComplete(pluginName);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      logger.severe("Scan interrupted");
    } finally {
      executor.shutdownNow();
    }
  }

  private static void printScanComplete(String pluginName) {
    System.out.println("\n╔═══════════════════════════════════════════════════════╗");
    System.out.println("  Scan completed for: " + pluginName);
    System.out.println("╚═══════════════════════════════════════════════════════╝\n");
  }
}
