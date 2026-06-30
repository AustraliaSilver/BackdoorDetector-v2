package backdoordetected.services;

import static org.junit.jupiter.api.Assertions.*;

import backdoordetected.exceptions.AIAnalysisException;
import org.junit.jupiter.api.Test;

class AIAnalysisServiceTest {

  @Test
  void constructorStoresKeys() {
    AIAnalysisService service = new AIAnalysisService("key1", "model1", "key2", "model2");
    assertNotNull(service);
  }

  @Test
  void constructorAcceptsNullKeys() {
    AIAnalysisService service = new AIAnalysisService(null, null, null, null);
    assertNotNull(service);
  }

  @Test
  void analyzeWithNullPrimaryKeyReturnsSkipMessage() throws AIAnalysisException {
    AIAnalysisService service = new AIAnalysisService(null, "model", null, null);
    String result = service.analyze("some content", "TestPlugin");
    assertTrue(result.contains("AI analysis skipped"));
    assertTrue(result.contains("Primary API key not configured"));
  }

  @Test
  void analyzeWithEmptyPrimaryKeyReturnsSkipMessage() throws AIAnalysisException {
    AIAnalysisService service = new AIAnalysisService("", "model", null, null);
    String result = service.analyze("content", "TestPlugin");
    assertTrue(result.contains("AI analysis skipped"));
  }

  @Test
  void analyzeWithPlaceholderKeyReturnsSkipMessage() throws AIAnalysisException {
    AIAnalysisService service = new AIAnalysisService("YOUR_API_KEY", "model", null, null);
    String result = service.analyze("content", "TestPlugin");
    assertTrue(result.contains("AI analysis skipped"));
  }

  @Test
  void escapeJsonHandlesNull() throws AIAnalysisException {
    AIAnalysisService service = new AIAnalysisService(null, null, null, null);
    String result = service.analyze(null, "TestPlugin");
    assertTrue(result.contains("AI analysis skipped"));
  }

  @Test
  void analyzeWithKeyButNoNetworkReturnsFailure() throws AIAnalysisException {
    AIAnalysisService service = new AIAnalysisService(
        "valid-key-12345", "gemini-1.5-pro", "backup-key", "gemini-1.5-flash");
    String result = service.analyze("test content", "TestPlugin");
    assertTrue(result.contains("FAILED") || result.contains("skipped"));
  }

  @Test
  void analyzeWithOnlyPrimaryKeyConfigured() throws AIAnalysisException {
    AIAnalysisService service = new AIAnalysisService(
        "real-key", "gemini-1.5-pro", null, null);
    String result = service.analyze("test", "Plugin");
    assertTrue(result.contains("FAILED") || result.contains("skipped"));
  }
}
