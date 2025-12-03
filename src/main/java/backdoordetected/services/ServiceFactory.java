package backdoordetected.services;

import backdoordetected.utils.ScanMode;
public class ServiceFactory {

  public static PluginOrchestrator createPluginOrchestrator(ScanMode mode) {
    ConfigService config = ConfigService.getInstance();
    DeobfuscationService deobfuscator = new DeobfuscationService();
    AnalysisCoordinator analyzer = new AnalysisCoordinator();
    ResultFormatter formatter = new ResultFormatter();
    AIAnalysisService aiService = null;

    if (mode.requiresApiKey()) {
      String apiKey1 = config.getProperty("gemini_api_key");
      String model1 = config.getProperty("gemini_model");
      String apiKey2 = config.getProperty("gemini_api_key_2");
      String model2 = config.getProperty("gemini_model_2");
      aiService = new AIAnalysisService(apiKey1, model1, apiKey2, model2);
    }

    return new PluginOrchestrator(deobfuscator, analyzer, aiService, formatter);
  }
}
