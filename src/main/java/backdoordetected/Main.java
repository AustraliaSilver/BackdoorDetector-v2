package backdoordetected;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
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

public class Main {
    private static final Logger logger = Logger.getLogger(Main.class.getName());
    private static final String VERSION = "1.0.2";
    private static final String CONFIG_FILE_NAME = "config.properties";

    public static String apiKey1;
    public static String model1;
    public static String apiKey2;
    public static String model2;
    private static boolean enableGemini2;

    public static void main(String[] args) {
        setupLogger();
        printBanner();

        createAndLoadConfig();

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
            if (!isApiKeyConfigured()) {
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
        executeScan(pluginFile, mode);
    }

    private static void printBanner() {
        System.out.println("\n╔═══════════════════════════════════════════════════════╗");
        System.out.println("║   Minecraft Plugin Backdoor Detector " + VERSION + "  ║");
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

    private static void executeScan(File pluginFile, ScanMode mode) {
        BlockingQueue<PluginWorker.PrioritizedFile> queue = new LinkedBlockingQueue<>();
        queue.offer(new PluginWorker.PrioritizedFile(pluginFile, 0));

        if (mode == ScanMode.AI_MODERN || mode == ScanMode.AI || mode == ScanMode.AI_BACKDOOR_FOCUS) {
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

    private static boolean createAndLoadConfig() {
        File configFile = new File(CONFIG_FILE_NAME);

        if (!configFile.exists()) {
            try (FileOutputStream fos = new FileOutputStream(configFile)) {
                Properties defaultProps = new Properties();
                defaultProps.setProperty("gemini_api_key", "YOUR_FIRST_API_KEY");
                defaultProps.setProperty("gemini_model", "gemini-2.5-pro");
                defaultProps.setProperty("enable_gemini_2", "true");
                defaultProps.setProperty("gemini_api_key_2", "YOUR_SECOND_API_KEY");
                defaultProps.setProperty("gemini_model_2", "gemini-2.5-flash");
                defaultProps.setProperty("codeql_executable_path", "");
                defaultProps.store(fos, "Backdoor Detector Configuration");

                System.out.println("Created config.properties file");
                System.out.println("Add your Gemini API keys to use AI features\n");
                return false;
            } catch (IOException e) {
                logger.severe("Could not create config.properties: " + e.getMessage());
                return false;
            }
        }

        Properties props = new Properties();
        try (FileInputStream fis = new FileInputStream(configFile)) {
            props.load(fis);
            apiKey1 = props.getProperty("gemini_api_key", "");
            model1 = props.getProperty("gemini_model", "gemini-2.0-flash-exp");
            enableGemini2 = Boolean.parseBoolean(props.getProperty("enable_gemini_2", "false"));
            apiKey2 = props.getProperty("gemini_api_key_2", "");
            model2 = props.getProperty("gemini_model_2", "gemini-2.0-flash-exp");
            return true;
        } catch (IOException e) {
            logger.severe("Could not load config.properties: " + e.getMessage());
            return false;
        }
    }

    public static String getConfigProperty(String key) {
        Properties props = new Properties();
        try (FileInputStream fis = new FileInputStream(CONFIG_FILE_NAME)) {
            props.load(fis);
            String value = props.getProperty(key);
            return (value == null || value.isBlank()) ? null : value;
        } catch (IOException e) {
            return null;
        }
    }

    public static void setConfigProperty(String key, String value) {
        Properties props = new Properties();
        try (FileInputStream fis = new FileInputStream(CONFIG_FILE_NAME)) {
            props.load(fis);
            props.setProperty(key, value);
            try (FileOutputStream fos = new FileOutputStream(CONFIG_FILE_NAME)) {
                props.store(fos, "Backdoor Detector Configuration");
            }
        } catch (IOException e) {
            logger.warning("Could not save property to config file: " + e.getMessage());
        }
    }

    private static boolean isApiKeyConfigured() {
        return apiKey1 != null &&
                !apiKey1.isEmpty() &&
                !apiKey1.equals("YOUR_FIRST_API_KEY") &&
                !apiKey1.startsWith("YOUR_");
    }

    private static void startSequentialScan(BlockingQueue<PluginWorker.PrioritizedFile> queue,
            ScanMode mode, String pluginName) {
        CountDownLatch latch = new CountDownLatch(1);
        ExecutorService executor = Executors.newFixedThreadPool(1);

        executor.submit(new PluginWorker(queue, apiKey1, model1, apiKey2, model2, "SCANNER", mode, latch));

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

    private static void startParallelScan(BlockingQueue<PluginWorker.PrioritizedFile> queue,
            ScanMode mode, String pluginName) {
        int numThreads = Math.max(1, Runtime.getRuntime().availableProcessors() / 2);
        logger.info("Starting parallel scan with " + numThreads + " worker threads.");

        ExecutorService executor = Executors.newFixedThreadPool(numThreads);
        CountDownLatch latch = new CountDownLatch(numThreads);

        for (int i = 0; i < numThreads; i++) {
            executor.submit(
                    new PluginWorker(queue, apiKey1, model1, apiKey2, model2, "WORKER-" + (i + 1), mode, latch));
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