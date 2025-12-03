package backdoordetected.plugins;

import backdoordetected.utils.ScanMode;
import backdoordetected.utils.StandaloneLogger;
import java.util.*;
import java.util.logging.Logger;
import java.util.stream.Collectors;
public class AnalyzerRegistry {
  private static final Logger logger = StandaloneLogger.getLogger();
  private static volatile AnalyzerRegistry instance;

  private final List<PluginAnalyzer> analyzers;
  private final Map<String, PluginAnalyzer> analyzersByName;

  private AnalyzerRegistry() {
    this.analyzers = discoverAnalyzers();
    this.analyzersByName =
        analyzers.stream().collect(Collectors.toMap(PluginAnalyzer::getName, a -> a));
  }

  public static AnalyzerRegistry getInstance() {
    if (instance == null) {
      synchronized (AnalyzerRegistry.class) {
        if (instance == null) {
          instance = new AnalyzerRegistry();
        }
      }
    }
    return instance;
  }

  private List<PluginAnalyzer> discoverAnalyzers() {
    ServiceLoader<PluginAnalyzer> loader = ServiceLoader.load(PluginAnalyzer.class);
    List<PluginAnalyzer> found = new ArrayList<>();

    for (PluginAnalyzer analyzer : loader) {
      logger.info(
          "Discovered analyzer: "
              + analyzer.getName()
              + " (priority: "
              + analyzer.getPriority()
              + ")");
      found.add(analyzer);
    }

    found.sort(Comparator.comparingInt(PluginAnalyzer::getPriority));

    logger.info("Loaded " + found.size() + " plugin analyzer(s)");
    return found;
  }

  public List<PluginAnalyzer> getAnalyzersForMode(ScanMode mode) {
    return analyzers.stream()
        .filter(
            a -> {
              Set<ScanMode> supported = a.getSupportedModes();
              return supported.isEmpty() || supported.contains(mode);
            })
        .collect(Collectors.toList());
  }

  public List<PluginAnalyzer> getAllAnalyzers() {
    return new ArrayList<>(analyzers);
  }

  public Optional<PluginAnalyzer> getAnalyzer(String name) {
    return Optional.ofNullable(analyzersByName.get(name));
  }

  public boolean hasAnalyzer(String name) {
    return analyzersByName.containsKey(name);
  }

  public int getAnalyzerCount() {
    return analyzers.size();
  }

  public synchronized void reload() {
    instance = null;
    getInstance();
  }
}
