package backdoordetected.services;

import backdoordetected.models.DecompilationResult;
import backdoordetected.utils.StandaloneLogger;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.stats.CacheStats;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;
public class CacheService {
  private static final Logger logger = StandaloneLogger.getLogger();

  private final Cache<String, DecompilationResult> decompilationCache;
  private final Cache<String, String> aiResultCache;

  public CacheService() {
    this.decompilationCache =
        Caffeine.newBuilder()
            .maximumSize(100)
            .expireAfterWrite(24, TimeUnit.HOURS)
            .recordStats()
            .build();

    this.aiResultCache =
        Caffeine.newBuilder()
            .maximumSize(50)
            .expireAfterWrite(1, TimeUnit.HOURS)
            .recordStats()
            .build();

    logger.info(
        "CacheService initialized: decompilation(100 entries, 24h TTL), AI(50 entries, 1h TTL)");
  }

  public Optional<DecompilationResult> getDecompilation(String hash) {
    DecompilationResult result = decompilationCache.getIfPresent(hash);
    if (result != null) {
      logger.fine("Decompilation cache HIT for hash: " + hash.substring(0, 8) + "...");
    } else {
      logger.fine("Decompilation cache MISS for hash: " + hash.substring(0, 8) + "...");
    }
    return Optional.ofNullable(result);
  }

  public void putDecompilation(String hash, DecompilationResult result) {
    decompilationCache.put(hash, result);
    logger.fine("Cached decompilation for hash: " + hash.substring(0, 8) + "...");
  }

  public Optional<String> getAIResult(String codeHash) {
    String result = aiResultCache.getIfPresent(codeHash);
    if (result != null) {
      logger.fine("AI cache HIT for hash: " + codeHash.substring(0, 8) + "...");
    } else {
      logger.fine("AI cache MISS for hash: " + codeHash.substring(0, 8) + "...");
    }
    return Optional.ofNullable(result);
  }

  public void putAIResult(String codeHash, String result) {
    aiResultCache.put(codeHash, result);
    logger.fine("Cached AI result for hash: " + codeHash.substring(0, 8) + "...");
  }

  public void logCacheStats() {
    CacheStats decompStats = decompilationCache.stats();
    CacheStats aiStats = aiResultCache.stats();

    logger.info("=== Cache Statistics ===");
    logger.info("Decompilation Cache:");
    logger.info("  Hit rate: " + String.format("%.2f%%", decompStats.hitRate() * 100));
    logger.info("  Hits: " + decompStats.hitCount());
    logger.info("  Misses: " + decompStats.missCount());
    logger.info("  Size: " + decompilationCache.estimatedSize());

    logger.info("AI Result Cache:");
    logger.info("  Hit rate: " + String.format("%.2f%%", aiStats.hitRate() * 100));
    logger.info("  Hits: " + aiStats.hitCount());
    logger.info("  Misses: " + aiStats.missCount());
    logger.info("  Size: " + aiResultCache.estimatedSize());
  }

  public void clearAll() {
    decompilationCache.invalidateAll();
    aiResultCache.invalidateAll();
    logger.info("All caches cleared");
  }
}
