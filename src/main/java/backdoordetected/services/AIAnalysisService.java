package backdoordetected.services;

import backdoordetected.exceptions.AIAnalysisException;
import backdoordetected.utils.StandaloneLogger;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import org.json.JSONObject;
public class AIAnalysisService {
  private static final Logger logger = StandaloneLogger.getLogger();

  private final String primaryApiKey;
  private final String primaryModelName;
  private final String secondaryApiKey;
  private final String secondaryModelName;

  private static final int CONNECT_TIMEOUT_MS = 15_000;
  private static final int READ_TIMEOUT_MS = 60_000;
  private static final int RETRY_DELAY_MS = 2_000;
  private static final int RATE_LIMIT_DELAY_MS = 5_000;

  public AIAnalysisService(
      String primaryApiKey,
      String primaryModelName,
      String secondaryApiKey,
      String secondaryModelName) {
    this.primaryApiKey = primaryApiKey;
    this.primaryModelName = primaryModelName;
    this.secondaryApiKey = secondaryApiKey;
    this.secondaryModelName = secondaryModelName;
  }

  public String analyze(String content, String pluginName) throws AIAnalysisException {
    if (primaryApiKey == null || primaryApiKey.isEmpty() || primaryApiKey.startsWith("YOUR_")) {
      return "AI analysis skipped: Primary API key not configured";
    }
    for (int i = 1; i <= 2; i++) {
      logger.info(
          "[Attempt " + i + "/2] Trying PRIMARY model: " + primaryModelName + " for " + pluginName);
      String result = trySendRequest(primaryModelName, primaryApiKey, content);
      if (result != null) {
        return result;
      }
    }

    logger.warning("Primary model failed 2 times. Switching to Secondary...");

    if (secondaryApiKey != null
        && !secondaryApiKey.isEmpty()
        && !secondaryApiKey.startsWith("YOUR_")) {
      for (int i = 1; i <= 2; i++) {
        logger.info(
            "[Attempt "
                + i
                + "/2] Trying SECONDARY model: "
                + secondaryModelName
                + " for "
                + pluginName);
        String result = trySendRequest(secondaryModelName, secondaryApiKey, content);
        if (result != null) {
          return result;
        }
      }
    } else {
      logger.warning("Secondary API key not configured. Skipping backup attempts.");
    }

    return "AI analysis FAILED after retries. Please check your API keys and quota.";
  }

  private String trySendRequest(String modelName, String apiKey, String content) {
    HttpURLConnection conn = null;
    try {
      String urlString =
          "https://generativelanguage.googleapis.com/v1beta/models/"
              + modelName
              + ":generateContent?key="
              + apiKey;

      URL url = new URL(urlString);
      conn = (HttpURLConnection) url.openConnection();
      conn.setRequestMethod("POST");
      conn.setRequestProperty("Content-Type", "application/json; charset=utf-8");
      conn.setConnectTimeout(CONNECT_TIMEOUT_MS);
      conn.setReadTimeout(READ_TIMEOUT_MS);
      conn.setDoOutput(true);

      String safeContent = escapeJson(content);
      String json = "{\"contents\": [{\"parts\": [{\"text\": \"" + safeContent + "\"}]}]}";

      try (OutputStream os = conn.getOutputStream()) {
        os.write(json.getBytes(StandardCharsets.UTF_8));
      }
      int code = conn.getResponseCode();
      InputStream is = (code >= 200 && code < 300) ? conn.getInputStream() : conn.getErrorStream();
      String responseStr = "";
      if (is != null) {
        try (BufferedReader br =
            new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
          responseStr = br.lines().collect(Collectors.joining("\n"));
        }
      }

      if (code == HttpURLConnection.HTTP_OK) {
        return parseSuccessResponse(responseStr, modelName);
      } else if (code == 429) {
        logger.warning("Rate limit (429) on " + modelName);
        Thread.sleep(RATE_LIMIT_DELAY_MS);
        return null;
      } else if (code == 503) {
        logger.warning("Service unavailable (503) on " + modelName);
        Thread.sleep(RATE_LIMIT_DELAY_MS);
        return null;
      } else {
        logger.warning("Error on " + modelName + " (HTTP " + code + "): " + responseStr);
        return null;
      }
    } catch (Exception e) {
      logger.warning("Connection error with " + modelName + ": " + e.getMessage());
      try {
        Thread.sleep(RETRY_DELAY_MS);
      } catch (InterruptedException ignored) {
        Thread.currentThread().interrupt();
      }
      return null;
    } finally {
      if (conn != null) {
        conn.disconnect();
      }
    }
  }

  private String parseSuccessResponse(String responseStr, String modelName) {
    try {
      JSONObject jr = new JSONObject(responseStr);
      if (!jr.has("candidates") || jr.getJSONArray("candidates").isEmpty()) {
        logger.warning(modelName + ": Blocked or no candidates");
        return null;
      }
      return jr.getJSONArray("candidates")
          .getJSONObject(0)
          .getJSONObject("content")
          .getJSONArray("parts")
          .getJSONObject(0)
          .getString("text");
    } catch (Exception e) {
      logger.warning("Failed to parse response from " + modelName + ": " + e.getMessage());
      return null;
    }
  }

  private String escapeJson(String text) {
    if (text == null) return "";
    return text.replace("\\", "\\\\")
        .replace("\"", "\\\"")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t");
  }
}
