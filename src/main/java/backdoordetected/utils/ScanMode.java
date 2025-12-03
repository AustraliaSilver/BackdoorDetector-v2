package backdoordetected.utils;

public enum ScanMode {
  AI_MODERN("Event detection + AI validation", true, true),
  AI_BACKDOOR_FOCUS("AI analysis focused on hidden backdoors", true, true),
  AI("Full AI analysis", false, true),
  MODERN("Event handler pattern scanning", true, false),
  BYTECODE("Bytecode-level analysis", true, false),
  SANDBOX("Event behavioral analysis", true, false),
  DATA_FLOW("Inter-procedural taint tracking", false, false),
  DEPENDENCY("Vulnerable dependency scanning", true, false),
  SYMBOLIC("Symbolic execution with Z3", false, false);

  private final String description;
  private final boolean fastMode;
  private final boolean requiresApiKey;

  ScanMode(String description, boolean fastMode, boolean requiresApiKey) {
    this.description = description;
    this.fastMode = fastMode;
    this.requiresApiKey = requiresApiKey;
  }

  public String getDescription() {
    return description;
  }

  public boolean isFastMode() {
    return fastMode;
  }

  public boolean requiresApiKey() {
    return requiresApiKey;
  }

  public static ScanMode getRecommendedMode(boolean hasApiKey, boolean needsFast) {
    if (hasApiKey && !needsFast) {
      return AI_MODERN;
    } else if (needsFast) {
      return MODERN;
    } else {
      return DATA_FLOW;
    }
  }

  public static void printAllModes() {
    System.out.println("\n═══ Available Scan Modes ═══");
    for (ScanMode mode : values()) {
      String speedLabel = mode.isFastMode() ? "[Fast]" : "[Thorough]";
      String apiLabel = mode.requiresApiKey() ? "[Requires API]" : "[No API needed]";
      System.out.printf(
          "  %-12s : %s %s %s\n", mode.name(), mode.description, speedLabel, apiLabel);
    }
    System.out.println("════════════════════════════\n");
  }
}
