package backdoordetected.services;

import backdoordetected.utils.ScanMode;
public class ServiceFactory {

  public static PluginOrchestrator createPluginOrchestrator(ScanMode mode) {
    ConfigService config = ConfigService.getInstance();
    DeobfuscationService deobfuscator = new DeobfuscationService();
    AnalysisCoordinator analyzer = new AnalysisCoordinator();
    ResultFormatter formatter = new ResultFormatter();
    AIAnalysisService aiService = null;
    BackendAnalysisService backendService = null;

    String primaryAi = config.getProperty("primary_ai", "backend");
    if ("backend".equalsIgnoreCase(primaryAi)) {
      String backendUrl = config.getProperty("ai_backend_url");
      if (backendUrl != null && !backendUrl.isEmpty() && !backendUrl.startsWith("YOUR_")) {
        backendService = new BackendAnalysisService(backendUrl);
      } else {
        backendService = new BackendAnalysisService();
      }
    }

    if (mode.requiresApiKey()) {
      String apiKey1 = config.getProperty("gemini_api_key");
      String model1 = config.getProperty("gemini_model");
      String apiKey2 = config.getProperty("gemini_api_key_2");
      String model2 = config.getProperty("gemini_model_2");
      aiService = new AIAnalysisService(apiKey1, model1, apiKey2, model2);
    }

    return new PluginOrchestrator(deobfuscator, analyzer, aiService, backendService, formatter);
  }
}
