package backdoordetected.services;

import backdoordetected.analyzers.*;
import backdoordetected.utils.StandaloneLogger;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.*;
import java.util.logging.Logger;


public class ParallelAnalysisCoordinator {
    private static final Logger logger = StandaloneLogger.getLogger();

    private final EventTriggerAnalyzer eventTriggerAnalyzer;
    private final DataFlowAnalyzer dataFlowAnalyzer;
    private final BytecodeAnalyzer bytecodeAnalyzer;
    private final ExecutorService executorService;

    
    public ParallelAnalysisCoordinator(int numThreads) {
        this.eventTriggerAnalyzer = new EventTriggerAnalyzer();
        this.dataFlowAnalyzer = new DataFlowAnalyzer();
        this.bytecodeAnalyzer = new BytecodeAnalyzer();
        this.executorService = Executors.newFixedThreadPool(
                Math.max(1, numThreads),
                r -> {
                    Thread t = new Thread(r);
                    t.setName("AnalyzerWorker-" + t.threadId());
                    t.setDaemon(true);
                    return t;
                });
    }

    
    public ParallelAnalysisResult analyzeParallel(
            List<Path> javaFiles,
            List<Path> classFiles,
            Path workingDir,
            boolean useDataFlow) {

        logger.info("Starting parallel analysis with " +
                (useDataFlow ? "DataFlow" : "EventTrigger") + " + Bytecode analyzers");

        long startTime = System.currentTimeMillis();

        try {
            
            CompletableFuture<Map<Path, List<String>>> eventOrDataFlowFuture;
            CompletableFuture<List<Path>> failedFilesFuture;

            if (useDataFlow) {
                
                eventOrDataFlowFuture = CompletableFuture.supplyAsync(() -> {
                    logger.info("[DataFlowAnalyzer] Starting analysis...");
                    DataFlowAnalyzer.AnalysisResult result = dataFlowAnalyzer.analyze(javaFiles, workingDir);

                    
                    Map<Path, List<String>> pathFindings = new ConcurrentHashMap<>();
                    result.findings().forEach((filename, findings) -> {
                        javaFiles.stream()
                                .filter(p -> p.getFileName().toString().equals(filename))
                                .findFirst()
                                .ifPresent(p -> pathFindings.put(p, findings));
                    });

                    logger.info("[DataFlowAnalyzer] Completed with " + pathFindings.size() + " findings");
                    return pathFindings;
                }, executorService);

                failedFilesFuture = CompletableFuture.supplyAsync(() -> {
                    DataFlowAnalyzer.AnalysisResult result = dataFlowAnalyzer.analyze(javaFiles, workingDir);
                    return result.failedFiles();
                }, executorService);

            } else {
                
                eventOrDataFlowFuture = CompletableFuture.supplyAsync(() -> {
                    logger.info("[EventTriggerAnalyzer] Starting analysis...");
                    EventTriggerAnalyzer.AnalysisResult result = eventTriggerAnalyzer.analyze(javaFiles);
                    logger.info("[EventTriggerAnalyzer] Completed with " + result.findings().size() + " findings");
                    return result.findings();
                }, executorService);

                failedFilesFuture = CompletableFuture.supplyAsync(() -> {
                    EventTriggerAnalyzer.AnalysisResult result = eventTriggerAnalyzer.analyze(javaFiles);
                    return result.failedFiles();
                }, executorService);
            }

            
            CompletableFuture<List<String>> bytecodeFuture = CompletableFuture.supplyAsync(() -> {
                logger.info("[BytecodeAnalyzer] Starting analysis of " + classFiles.size() + " class files...");
                List<String> findings = bytecodeAnalyzer.analyze(classFiles);
                logger.info("[BytecodeAnalyzer] Completed with " + findings.size() + " findings");
                return findings;
            }, executorService);

            
            CompletableFuture<Void> allOf = CompletableFuture.allOf(
                    eventOrDataFlowFuture,
                    failedFilesFuture,
                    bytecodeFuture);

            
            allOf.get(5, TimeUnit.MINUTES);

            
            Map<Path, List<String>> eventFindings = eventOrDataFlowFuture.get();
            List<Path> failedFiles = failedFilesFuture.get();
            List<String> bytecodeFindings = bytecodeFuture.get();

            long duration = System.currentTimeMillis() - startTime;
            logger.info("Parallel analysis completed in " + duration + "ms");

            return new ParallelAnalysisResult(eventFindings, failedFiles, bytecodeFindings);

        } catch (TimeoutException e) {
            logger.severe("Parallel analysis timed out after 5 minutes");
            throw new RuntimeException("Analysis timeout", e);

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            logger.severe("Parallel analysis interrupted");
            throw new RuntimeException("Analysis interrupted", e);

        } catch (ExecutionException e) {
            logger.severe("Parallel analysis failed: " + e.getCause().getMessage());
            throw new RuntimeException("Analysis failed", e.getCause());
        }
    }

    
    public void shutdown() {
        executorService.shutdown();
        try {
            if (!executorService.awaitTermination(10, TimeUnit.SECONDS)) {
                executorService.shutdownNow();
            }
        } catch (InterruptedException e) {
            executorService.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }

    
    public static class ParallelAnalysisResult {
        private final Map<Path, List<String>> eventFindings;
        private final List<Path> failedFiles;
        private final List<String> bytecodeFindings;

        public ParallelAnalysisResult(
                Map<Path, List<String>> eventFindings,
                List<Path> failedFiles,
                List<String> bytecodeFindings) {
            this.eventFindings = eventFindings;
            this.failedFiles = failedFiles;
            this.bytecodeFindings = bytecodeFindings;
        }

        public Map<Path, List<String>> getEventFindings() {
            return eventFindings;
        }

        public List<Path> getFailedFiles() {
            return failedFiles;
        }

        public List<String> getBytecodeFindings() {
            return bytecodeFindings;
        }
    }
}
