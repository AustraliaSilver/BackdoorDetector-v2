package backdoordetected;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.logging.ConsoleHandler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;
import backdoordetected.exceptions.AIAnalysisException;
import backdoordetected.exceptions.AnalysisException;
import backdoordetected.exceptions.DeobfuscationException;
import backdoordetected.models.PrioritizedFile;
import backdoordetected.services.*;
import backdoordetected.utils.ScanMode;
import backdoordetected.utils.StandaloneLogger;

public class Main {
    private static final Logger logger = Logger.getLogger(Main.class.getName());
    private static final String VERSION = "1.0.2";

    public static void main(String[] args) {
        setupLogger();
        printBanner();

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
            if (!isApiKeyConfigured(config)) {
                logger.severe("Scan mode " + mode.name() + " requires a valid Gemini API key.");
                logger.severe("   Please configure API key in config.properties");
                logger.info("\nAlternative: Use non-AI modes like DATA_FLOW or BYTECODE");
                return;
            }
        }

        File pluginFile = new File(pluginPath);
        if (!pluginFile.exists()) {
            logger.severe("Plugin file not found: " + pluginPath);
            return;
        }

        if (!pluginFile.getName().endsWith(".jar")) {
            logger.severe("Invalid file type. Expected .jar file, got: " + pluginFile.getName());
            return;
        }

        printScanHeader(pluginFile, mode);
        executeScan(pluginFile, mode, config);
    }

    private static void printBanner() {
        System.out.println("\n╔═══════════════════════════════════════════════════════╗");
        System.out.println("║   Minecraft Plugin Backdoor Detector " + VERSION + " ║");
        System.out.println("║           Advanced Security Analysis Tool             ║");
        System.out.println("╚═══════════════════════════════════════════════════════╝\n");
    }

    private static void printUsage() {
        System.out.println("USAGE:");
        System.out.println("  java -jar BackdoorDetect.jar scan <plugin-path> [mode]\n");

        System.out.println("EXAMPLES:");
        System.out.println("  java -jar BackdoorDetect.jar scan plugin.jar");
        System.out.println("  java -jar BackdoorDetect.jar scan plugin.jar AI_MODERN\n");

        ScanMode.printAllModes();

        System.out.println("RECOMMENDATIONS:");
        System.out.println("  • Best accuracy: AI_MODERN (requires API key)\n");
    }

    private static void printScanHeader(File pluginFile, ScanMode mode) {
        System.out.println("╔═══════════════════════════════════════════════════════╗");
        System.out.println("  Plugin: " + pluginFile.getName());
        System.out.println("  Mode: " + mode.name());
        System.out.println("  Description: " + mode.getDescription());
        System.out.println("╚═══════════════════════════════════════════════════════╝\n");
    }

    private static void executeScan(File pluginFile, ScanMode mode, ConfigService config) {
        BlockingQueue<PrioritizedFile> queue = new LinkedBlockingQueue<>();
        queue.offer(new PrioritizedFile(pluginFile, 0));

        boolean allowParallelAi = config.getBooleanProperty("ai_parallel_scanning", false);

        if (mode.requiresApiKey() && !allowParallelAi) {
            logger.info("AI scan mode detected. Running in sequential mode to avoid rate limits.");
            logger.info("To enable parallel AI scans, set 'ai_parallel_scanning=true' in config.properties.");
            startSequentialScan(queue, mode, pluginFile.getName());
        } else {
            startParallelScan(queue, mode, pluginFile.getName());
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

    private static void startSequentialScan(BlockingQueue<PrioritizedFile> queue,
            ScanMode mode, String pluginName) {
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

    private static void startParallelScan(BlockingQueue<PrioritizedFile> queue,
            ScanMode mode, String pluginName) {
        int numThreads = Math.max(1, Runtime.getRuntime().availableProcessors() / 2);
        logger.info("Starting parallel scan with " + numThreads + " worker threads.");

        ExecutorService executor = Executors.newFixedThreadPool(numThreads);
        CountDownLatch latch = new CountDownLatch(numThreads);
        PluginOrchestrator orchestrator = ServiceFactory.createPluginOrchestrator(mode);

        for (int i = 0; i < numThreads; i++) {
            executor.submit(
                    new PluginWorkerNew(queue, orchestrator, "WORKER-" + (i + 1), mode, latch));
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