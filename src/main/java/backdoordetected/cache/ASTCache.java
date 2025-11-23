package backdoordetected.cache;

import backdoordetected.utils.StandaloneLogger;
import com.github.javaparser.JavaParser;
import com.github.javaparser.ParseResult;
import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

public class ASTCache {
    private static final Logger logger = StandaloneLogger.getLogger();
    private static final Map<String, CachedAST> cache = new ConcurrentHashMap<>();
    private static final int MAX_CACHE_SIZE = 1000;
    private static int hits = 0;
    private static int misses = 0;

    private static class CachedAST {
        final CompilationUnit ast;
        final long timestamp;

        CachedAST(CompilationUnit ast, long timestamp) {
            this.ast = ast;
            this.timestamp = timestamp;
        }
    }

    public static CompilationUnit parse(Path file) throws IOException {
        long lastModified = Files.getLastModifiedTime(file).toMillis();
        String key = file.toAbsolutePath().toString();
        CachedAST cached = cache.get(key);
        if (cached != null && cached.timestamp == lastModified) {
            synchronized (ASTCache.class) {
                hits++;
            }
            logger.fine("AST cache hit: " + file.getFileName());
            return cached.ast;
        }
        synchronized (ASTCache.class) {
            misses++;
        }
        logger.fine("AST cache miss: " + file.getFileName());
        CompilationUnit ast = StaticJavaParser.parse(file);
        if (cache.size() >= MAX_CACHE_SIZE) {
            evictOldest();
        }
        cache.put(key, new CachedAST(ast, lastModified));
        return ast;
    }

    public static ParseResult<CompilationUnit> parse(JavaParser parser, Path file) throws IOException {
        long lastModified = Files.getLastModifiedTime(file).toMillis();
        String key = file.toAbsolutePath().toString();
        CachedAST cached = cache.get(key);
        if (cached != null && cached.timestamp == lastModified) {
            synchronized (ASTCache.class) {
                hits++;
            }
            logger.fine("AST cache hit (re-parsing for ParseResult): " + file.getFileName());
        } else {
            synchronized (ASTCache.class) {
                misses++;
            }
            logger.fine("AST cache miss: " + file.getFileName());
        }

        ParseResult<CompilationUnit> result = parser.parse(file);

        if (result.isSuccessful() && result.getResult().isPresent()) {
            CompilationUnit ast = result.getResult().get();
            if (cached == null || cached.timestamp != lastModified) {
                if (cache.size() >= MAX_CACHE_SIZE) {
                    evictOldest();
                }

                cache.put(key, new CachedAST(ast, lastModified));
            }
        }

        return result;
    }

    private static void evictOldest() {
        if (cache.size() > MAX_CACHE_SIZE / 2) {
            List<String> keys = new ArrayList<>(cache.keySet());
            int toRemove = keys.size() / 2;

            logger.info(String.format("AST cache full (%d entries), evicting %d oldest entries",
                    cache.size(), toRemove));

            for (int i = 0; i < toRemove; i++) {
                cache.remove(keys.get(i));
            }
        }
    }

    public static void clear() {
        cache.clear();
        synchronized (ASTCache.class) {
            hits = 0;
            misses = 0;
        }
        logger.info("AST cache cleared");
    }

    public static void invalidate(Path file) {
        String key = file.toAbsolutePath().toString();
        cache.remove(key);
        logger.fine("AST cache invalidated: " + file.getFileName());
    }

    public static Map<String, Integer> getStats() {
        int totalRequests;
        int hitRate;

        synchronized (ASTCache.class) {
            totalRequests = hits + misses;
            hitRate = totalRequests > 0 ? (hits * 100 / totalRequests) : 0;
        }

        return Map.of(
                "hits", hits,
                "misses", misses,
                "hitRate", hitRate,
                "cacheSize", cache.size());
    }

    public static void logStats() {
        Map<String, Integer> stats = getStats();
        logger.info(String.format(
                "AST Cache Stats: %d hits, %d misses, %d%% hit rate, %d entries cached",
                stats.get("hits"), stats.get("misses"), stats.get("hitRate"), stats.get("cacheSize")));
    }
}
