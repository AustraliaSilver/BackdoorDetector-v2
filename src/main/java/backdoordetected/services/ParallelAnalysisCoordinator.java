package backdoordetected.services;

import backdoordetected.analyzers.*;
import backdoordetected.models.BytecodeAnalysisResult;
import backdoordetected.models.DataFlowAnalysisResult;
import backdoordetected.models.EventTriggerAnalysisResult;
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
    this.executorService =
        Executors.newFixedThreadPool(
            Math.max(1, numThreads),
            r -> {
              Thread t = new Thread(r);
              t.setName("AnalyzerWorker-" + t.threadId());
              t.setDaemon(true);
              return t;
            });
  }

  public ParallelAnalysisResult analyzeParallel(
      List<Path> javaFiles, List<Path> classFiles, Path workingDir, boolean useDataFlow) {

    logger.info(
        "Starting parallel analysis with "
            + (useDataFlow ? "DataFlow" : "EventTrigger")
            + " + Bytecode analyzers");

    long startTime = System.currentTimeMillis();

    try {

      CompletableFuture<Map<Path, List<String>>> eventOrDataFlowFuture;
      CompletableFuture<List<Path>> failedFilesFuture;

      if (useDataFlow) {

        CompletableFuture<DataFlowAnalysisResult> dfFuture =
            CompletableFuture.supplyAsync(
                () -> {
                  logger.info("[DataFlowAnalyzer] Starting analysis...");
                  try {
                    DataFlowAnalysisResult result =
                        (DataFlowAnalysisResult) dataFlowAnalyzer.analyze(javaFiles, workingDir);
                    logger.info(
                        "[DataFlowAnalyzer] Completed with "
                            + result.getFileFindings().size()
                            + " findings");
                    return result;
                  } catch (Exception e) {
                    logger.severe("[DataFlowAnalyzer] Failed: " + e.getMessage());
                    return null;
                  }
                },
                executorService);

        eventOrDataFlowFuture =
            dfFuture.thenApply(
                result -> {
                  if (result == null) {
                    return new HashMap<Path, List<String>>();
                  }
                  Map<Path, List<String>> pathFindings = new ConcurrentHashMap<>();
                  result
                      .getFileFindings()
                      .forEach(
                          (filename, findings) -> {
                            javaFiles.stream()
                                .filter(p -> p.getFileName().toString().equals(filename))
                                .findFirst()
                                .ifPresent(p -> pathFindings.put(p, findings));
                          });
                  return pathFindings;
                });

        failedFilesFuture =
            dfFuture.thenApply(
                result -> {
                  if (result == null) {
                    return new ArrayList<Path>();
                  }
                  return result.getFailedFiles();
                });

      } else {

        eventOrDataFlowFuture =
            CompletableFuture.supplyAsync(
                () -> {
                  logger.info("[EventTriggerAnalyzer] Starting analysis...");
                  try {
                    EventTriggerAnalysisResult result =
                        (EventTriggerAnalysisResult)
                            eventTriggerAnalyzer.analyze(
                                null,
                                javaFiles,
                                classFiles,
                                workingDir,
                                backdoordetected.utils.ScanMode.AI_MODERN,
                                "Parallel-EventTrigger");
                    logger.info(
                        "[EventTriggerAnalyzer] Completed with "
                            + result.getFileFindings().size()
                            + " findings");
                    Map<Path, List<String>> pathFindings = new ConcurrentHashMap<>();
                    result
                        .getFileFindings()
                        .forEach(
                            (filename, findings) -> {
                              javaFiles.stream()
                                  .filter(p -> p.getFileName().toString().equals(filename))
                                  .findFirst()
                                  .ifPresent(p -> pathFindings.put(p, findings));
                            });
                    return pathFindings;
                  } catch (Exception e) {
                    logger.severe("[EventTriggerAnalyzer] Failed: " + e.getMessage());
                    return new HashMap<>();
                  }
                },
                executorService);

        failedFilesFuture =
            CompletableFuture.supplyAsync(
                () -> {
                  try {
                    EventTriggerAnalysisResult result =
                        (EventTriggerAnalysisResult)
                            eventTriggerAnalyzer.analyze(
                                null,
                                javaFiles,
                                classFiles,
                                workingDir,
                                backdoordetected.utils.ScanMode.AI_MODERN,
                                "Parallel-EventTrigger");
                    return result.getFailedFiles();
                  } catch (Exception e) {
                    return new ArrayList<>();
                  }
                },
                executorService);
      }

      CompletableFuture<List<String>> bytecodeFuture =
          CompletableFuture.supplyAsync(
              () -> {
                logger.info(
                    "[BytecodeAnalyzer] Starting analysis of "
                        + classFiles.size()
                        + " class files...");
                try {
                  BytecodeAnalysisResult result =
                      (BytecodeAnalysisResult)
                          bytecodeAnalyzer.analyze(
                              null,
                              javaFiles,
                              classFiles,
                              workingDir,
                              backdoordetected.utils.ScanMode.AI_MODERN,
                              "Parallel-Bytecode");
                  List<String> findings = result.getRawFindings();
                  logger.info("[BytecodeAnalyzer] Completed with " + findings.size() + " findings");
                  return findings;
                } catch (Exception e) {
                  logger.severe("[BytecodeAnalyzer] Failed: " + e.getMessage());
                  return new ArrayList<>();
                }
              },
              executorService);

      CompletableFuture<Void> allOf =
          CompletableFuture.allOf(eventOrDataFlowFuture, failedFilesFuture, bytecodeFuture);

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
