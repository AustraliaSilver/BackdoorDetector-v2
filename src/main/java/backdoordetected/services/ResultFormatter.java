package backdoordetected.services;

import backdoordetected.detection.LMXBackdoorDetector;
import backdoordetected.utils.StandaloneLogger;
import java.nio.file.Path;
import java.util.logging.Logger;

public class ResultFormatter {
    private static final Logger logger = StandaloneLogger.getLogger();

    public String formatResult(String aiResult,
            LMXBackdoorDetector.BackdoorScanResult backdoorScan,
            boolean lmxStringLiteralFound) {
        if (backdoorScan.hasLMXBackdoor || backdoorScan.hasOpenEctasy || lmxStringLiteralFound) {
            return buildKnownBackdoorResult(backdoorScan, lmxStringLiteralFound);
        }
        if (aiResult != null && !aiResult.isBlank()) {
            return aiResult;
        }
        return "No analysis result available";
    }

    private String buildKnownBackdoorResult(LMXBackdoorDetector.BackdoorScanResult backdoorScan,
            boolean lmxStringLiteralFound) {
        StringBuilder result = new StringBuilder();
        result.append("**Malicious:** YES\n");
        result.append("**Confidence:** 100%\n");
        result.append("**Severity:** CRITICAL\n");
        result.append("**Vulnerability Type:** Hardcoded Backdoor\n\n");
        result.append("### BRIEF REASONING\n");

        if (backdoorScan.hasLMXBackdoor) {
            result.append("- Confirmed: L.M.X backdoor signature detected (sequential L/M/X directory structure).\n");
        }
        if (backdoorScan.hasOpenEctasy) {
            result.append("- Confirmed: OpenEctasy malware signature detected ('bodyalhoha' directory).\n");
        }
        if (lmxStringLiteralFound) {
            result.append("- Confirmed: L.M.X backdoor pattern found as string literal in decompiled code. ");
            result.append(
                    "This indicates a strong likelihood of the plugin being the L.M.X backdoor itself or a variant.\n");
        }

        result.append("This is an unequivocally known and critical backdoor/malware pattern, ");
        result.append("regardless of other contextual factors or potential decompiler artifacts. ");
        result.append("All such detections are treated as highly dangerous.");

        return result.toString();
    }

    public void logFormattedResult(String result) {
        logger.info("╔" + "═".repeat(80) + "╗");
        logger.info("║" + " ".repeat(34) + " AI ANALYSIS RESULT " + " ".repeat(28) + "║");
        logger.info("╠" + "═".repeat(80) + "╣");

        for (String line : result.split("\n")) {
            logger.info("║ " + line);
        }

        logger.info("╚" + "═".repeat(80) + "╝");
    }
}
