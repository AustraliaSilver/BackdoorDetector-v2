package backdoordetected.services;

import backdoordetected.exceptions.AnalysisException;
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
    private final ResultFormatter resultFormatter;
    private final AIPromptBuilder promptBuilder;

    public PluginOrchestrator(DeobfuscationService deobfuscationService,
            AnalysisCoordinator analysisCoordinator,
            AIAnalysisService aiAnalysisService,
            ResultFormatter resultFormatter) {
        this.deobfuscationService = deobfuscationService;
        this.analysisCoordinator = analysisCoordinator;
        this.aiAnalysisService = aiAnalysisService;
        this.resultFormatter = resultFormatter;
        this.promptBuilder = new AIPromptBuilder();
    }

    public String scan(Path pluginPath, ScanMode scanMode, String workerName) {
        try {
            logger.info("[" + workerName + "] Starting scan for " + pluginPath.getFileName());
            Path pathToAnalyze = deobfuscationService.deobfuscate(pluginPath);
            ComprehensiveAnalysisResult analysis = analysisCoordinator.analyze(
                    pathToAnalyze, scanMode, workerName);
            if (!analysis.hasHighSeverityFindings()) {
                if (analysis.hasFindings()) {
                    logger.info("Only LOW severity findings detected; skipping AI analyze.");
                } else {
                    logger.info("No suspicious triggers found; skipping AI analyze.");
                }
                return "**Malicious:** NO\n**Confidence:** 95%\n**Severity:** NONE\n**Vulnerability Type:** Clean\n\n### BRIEF REASONING\nNo high-severity suspicious patterns detected.";
            }
            String aiResult = null;
            if (scanMode == ScanMode.AI_MODERN || scanMode == ScanMode.AI || scanMode == ScanMode.AI_BACKDOOR_FOCUS) {
                String prompt = buildPrompt(analysis);
                aiResult = aiAnalysisService.analyze(prompt, pluginPath.getFileName().toString());
            }

            String formattedResult = resultFormatter.formatResult(
                    aiResult,
                    analysis.backdoorScan(),
                    analysis.lmxStringLiteralFound());

            resultFormatter.logFormattedResult(formattedResult);

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
        List<String> suspiciousFileNames = analysis.suspiciousFiles().stream()
                .map(p -> sanitizeForPrompt(p.getFileName().toString()))
                .collect(Collectors.toList());

        String findings = formatEventFindings(analysis.eventFindings());

        return promptBuilder
                .withSuspiciousFiles(suspiciousFileNames)
                .withFindings(findings)
                .withCode(analysis.combinedCode())
                .withDirectoryTree(analysis.directoryTree())
                .withKnownBackdoorDetected(analysis.hasKnownBackdoor())
                .build();
    }

    private String sanitizeForPrompt(String input) {
        if (input == null)
            return "";
        return input.replaceAll("[^a-zA-Z0-9._-]", "_");
    }

    private String formatEventFindings(java.util.Map<Path, List<String>> findings) {
        if (findings == null || findings.isEmpty())
            return "";
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
