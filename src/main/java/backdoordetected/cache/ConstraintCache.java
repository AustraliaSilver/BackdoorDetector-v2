package backdoordetected.cache;

import com.microsoft.z3.BoolExpr;
import com.microsoft.z3.Status;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;
import backdoordetected.utils.StandaloneLogger;

public class ConstraintCache implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final Logger logger = StandaloneLogger.getLogger();
    private final Map<String, CachedConstraintResult> cache;
    private int hits = 0;
    private int misses = 0;

    public ConstraintCache() {
        this.cache = new HashMap<>();
    }

    public boolean isCached(BoolExpr constraint) {
        String key = computeKey(constraint);
        return cache.containsKey(key);
    }

    public CachedConstraintResult get(BoolExpr constraint) {
        String key = computeKey(constraint);
        CachedConstraintResult result = cache.get(key);

        if (result != null) {
            hits++;
            logger.fine("Constraint cache HIT: " + key);
        } else {
            misses++;
            logger.fine("Constraint cache MISS: " + key);
        }

        return result;
    }

    public void put(BoolExpr constraint, Status status, String model) {
        String key = computeKey(constraint);
        cache.put(key, new CachedConstraintResult(status, model, System.currentTimeMillis()));
        logger.fine("Cached constraint result: " + key + " -> " + status);
    }

    private String computeKey(BoolExpr constraint) {
        return constraint.toString().hashCode() + "_" + constraint.hashCode();
    }

    public void clear() {
        cache.clear();
        hits = 0;
        misses = 0;
        logger.info("Constraint cache cleared");
    }

    public CacheStats getStats() {
        return new CacheStats(cache.size(), hits, misses);
    }

    public void save(Path cacheFile) throws IOException {
        Files.createDirectories(cacheFile.getParent());

        try (ObjectOutputStream oos = new ObjectOutputStream(
                new BufferedOutputStream(Files.newOutputStream(cacheFile)))) {
            oos.writeObject(this);
            logger.info("Saved constraint cache to: " + cacheFile + " (entries: " + cache.size() + ")");
        }
    }

    public static ConstraintCache load(Path cacheFile) throws IOException {
        if (!Files.exists(cacheFile)) {
            logger.info("No constraint cache file found, starting fresh");
            return new ConstraintCache();
        }

        try (ObjectInputStream ois = new ObjectInputStream(
                new BufferedInputStream(Files.newInputStream(cacheFile)))) {
            ConstraintCache cache = (ConstraintCache) ois.readObject();
            logger.info("Loaded constraint cache from: " + cacheFile + " (entries: " + cache.cache.size() + ")");
            return cache;
        } catch (ClassNotFoundException e) {
            logger.warning("Failed to load constraint cache: " + e.getMessage());
            return new ConstraintCache();
        }
    }

    public static class CachedConstraintResult implements Serializable {
        private static final long serialVersionUID = 1L;

        private final Status status;
        private final String model;
        private final long timestamp;

        public CachedConstraintResult(Status status, String model, long timestamp) {
            this.status = status;
            this.model = model;
            this.timestamp = timestamp;
        }

        public Status getStatus() {
            return status;
        }

        public String getModel() {
            return model;
        }

        public long getTimestamp() {
            return timestamp;
        }
    }

    public static class CacheStats {
        private final int size;
        private final int hits;
        private final int misses;

        public CacheStats(int size, int hits, int misses) {
            this.size = size;
            this.hits = hits;
            this.misses = misses;
        }

        public int getSize() {
            return size;
        }

        public int getHits() {
            return hits;
        }

        public int getMisses() {
            return misses;
        }

        public double getHitRate() {
            int total = hits + misses;
            return total == 0 ? 0.0 : (double) hits / total;
        }

        @Override
        public String toString() {
            return String.format(
                    "ConstraintCache[size=%d, hits=%d, misses=%d, hit_rate=%.2f%%]",
                    size, hits, misses, getHitRate() * 100);
        }
    }
}
