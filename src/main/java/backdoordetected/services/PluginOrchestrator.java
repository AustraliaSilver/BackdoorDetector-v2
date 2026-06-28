package backdoordetected.services;

import backdoordetected.exceptions.AnalysisException;
import backdoordetected.models.BackendAnalysisResult;
import backdoordetected.models.ComprehensiveAnalysisResult;
import backdoordetected.utils.ScanMode;
import backdoordetected.utils.StandaloneLogger;
import java.nio.file.Path;
import java.util.List;
import java.util.logging.Logger;
import java.util.stream.Collectors;

public class PluginOrchestrator {
  private static final Logger logger = StandaloneLogger.getLogger();

  private final DeobfuscationService deobfuscationService;
  private final AnalysisCoordinator analysisCoordinator;
  private final AIAnalysisService aiAnalysisService;
  private final BackendAnalysisService backendAnalysisService;
  private final ResultFormatter resultFormatter;
  private final AIPromptBuilder promptBuilder;

private final String primaryAi;

   public PluginOrchestrator(
       DeobfuscationService deobfuscationService,
       AnalysisCoordinator analysisCoordinator,
       AIAnalysisService aiAnalysisService,
       BackendAnalysisService backendAnalysisService,
       ResultFormatter resultFormatter) {
     this(deobfuscationService, analysisCoordinator, aiAnalysisService, backendAnalysisService, resultFormatter, null);
   }

   public PluginOrchestrator(
       DeobfuscationService deobfuscationService,
       AnalysisCoordinator analysisCoordinator,
       AIAnalysisService aiAnalysisService,
       BackendAnalysisService backendAnalysisService,
       ResultFormatter resultFormatter,
       String primaryAi) {
     this.deobfuscationService = deobfuscationService;
     this.analysisCoordinator = analysisCoordinator;
     this.aiAnalysisService = aiAnalysisService;
     this.backendAnalysisService = backendAnalysisService;
     this.resultFormatter = resultFormatter;
     this.promptBuilder = new AIPromptBuilder();
     this.primaryAi = primaryAi != null ? primaryAi.toLowerCase() : "backend";
   }

  public String scan(Path pluginPath, ScanMode scanMode, String workerName) {
    try {
      logger.info("[" + workerName + "] Starting scan for " + pluginPath.getFileName());
      Path pathToAnalyze = deobfuscationService.deobfuscate(pluginPath);
      ComprehensiveAnalysisResult analysis =
          analysisCoordinator.analyze(pathToAnalyze, scanMode, workerName);

boolean hasSuspiciousFiles = !analysis.suspiciousFiles().isEmpty();
       boolean hasFindings = analysis.hasFindings();

      if (!hasSuspiciousFiles && !hasFindings) {
        logger.info("No suspicious files or triggers found; skipping AI analyze.");
        return "**Malicious:** NO\n**Confidence:** 95%\n**Severity:** NONE\n**Vulnerability Type:** Clean\n\n### BRIEF REASONING\nNo suspicious patterns or files detected.";
      }

      if (scanMode == ScanMode.AI_MODERN
          || scanMode == ScanMode.AI
          || scanMode == ScanMode.AI_BACKDOOR_FOCUS) {

        logger.info("Findings detected. Analyzing via AI...");

        String aiResult = null;

        if (backendAnalysisService != null) {
          logger.info("Trying local AI backend...");
          BackendAnalysisResult backendResult = backendAnalysisService.analyze(
              pluginPath, analysis, workerName);
          if (backendResult != null) {
            return formatBackendResult(backendResult);
          }
          logger.warning("Local AI backend failed or unavailable. Falling back to Gemini...");
        }

        if (aiAnalysisService != null) {
          String prompt = buildPrompt(analysis);
          aiResult = aiAnalysisService.analyze(prompt, pluginPath.getFileName().toString());
        }

        if (aiResult != null && !aiResult.isEmpty()) {
          return aiResult;
        }
      }

      String formattedResult = resultFormatter.formatResult(analysis);
      return formattedResult;

    } catch (AnalysisException e) {
      logger.severe("Scan failed for " + pluginPath.getFileName() + ": " + e.getMessage());
      return "**Malicious:** UNKNOWN\n**Confidence:** 0%\n**Severity:** ERROR\n\n### ERROR\nScan failed: "
          + e.getMessage();
    } catch (Exception e) {
      logger.severe("Unexpected error: " + e.getMessage());
      e.printStackTrace();
      return "**Malicious:** UNKNOWN\n**Confidence:** 0%\n**Severity:** ERROR\n\n### ERROR\nUnexpected error: "
          + e.getMessage();
    }
  }

  private String buildPrompt(ComprehensiveAnalysisResult analysis) {
    List<String> suspiciousFileNames =
        analysis.suspiciousFiles().stream()
            .map(p -> sanitizeForPrompt(p.getFileName().toString()))
            .collect(Collectors.toList());

    if (!suspiciousFileNames.isEmpty()) {
      logger.info("═══════════════════════════════════════════════════════");
      logger.info(
          "Sending " + suspiciousFileNames.size() + " suspicious file(s) to AI for analysis:");
      for (String fileName : suspiciousFileNames) {
        logger.info("  → " + fileName);
      }
      logger.info("═══════════════════════════════════════════════════════");
    } else {
      logger.info("No suspicious files to send to AI (only metadata/findings)");
    }

    String findings = formatEventFindings(analysis.eventFindings());

    if (analysis.obfuscationResult().isHeavilyObfuscated()) {
      findings +=
          "\n\nWARNING: HEAVY OBFUSCATION DETECTED (Score: "
              + analysis.obfuscationResult().score()
              + ")\n";
      for (String warning : analysis.obfuscationResult().warnings()) {
        findings += "- " + warning + "\n";
      }
    }

    return promptBuilder
        .withSuspiciousFiles(suspiciousFileNames)
        .withFindings(findings)
        .withCode(analysis.combinedCode())
        .withDirectoryTree(analysis.directoryTree())
        .withKnownBackdoorDetected(analysis.hasKnownBackdoor())
        .build();
  }

  private String sanitizeForPrompt(String input) {
    if (input == null) return "";
    return input.replaceAll("[^a-zA-Z0-9._-]", "_");
  }

  private String formatBackendResult(BackendAnalysisResult result) {
    StringBuilder sb = new StringBuilder();
    sb.append("**Malicious:** ").append(result.isMalicious() ? "YES" : "NO").append("\n");
    sb.append("**Confidence:** ").append(result.confidence()).append("\n");
    sb.append("**Risk Score:** ").append(result.riskScore()).append("/100").append("\n");
    sb.append("**Threat Type:** ").append(result.threatType()).append("\n");
    sb.append("\n### SUMMARY\n").append(result.summary()).append("\n\n");
    sb.append("### ANALYSIS\n").append(result.analysis()).append("\n");

    if (!result.keyIndicators().isEmpty()) {
      sb.append("\n### KEY INDICATORS\n");
      for (String ind : result.keyIndicators()) {
        sb.append("- ").append(ind).append("\n");
      }
    }

    if (result.cached()) {
      sb.append("\n_(cached result, ").append(result.elapsedMs()).append("ms)_\n");
    }
    return sb.toString();
  }

  private String formatEventFindings(java.util.Map<Path, List<String>> findings) {
    if (findings == null || findings.isEmpty()) return "";
    StringBuilder sb = new StringBuilder();
    for (var entry : findings.entrySet()) {
      sb.append("File: ").append(entry.getKey().getFileName()).append("\n");
      for (String f : entry.getValue()) {
        sb.append("  • ").append(f).append("\n");
      }
    }
    return sb.toString();
  }
}
