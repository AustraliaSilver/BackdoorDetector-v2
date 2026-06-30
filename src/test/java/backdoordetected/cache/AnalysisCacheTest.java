package backdoordetected.cache;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class AnalysisCacheTest {

  private AnalysisCache cache;

  @TempDir
  Path tempDir;

  @BeforeEach
  void setUp() {
    cache = new AnalysisCache();
  }

  @Test
  void newCacheHasNoEntries() {
    Map<String, Integer> stats = cache.getStats();
    assertEquals(0, stats.get("totalFiles"));
    assertEquals(0, stats.get("cachedFindings"));
  }

  @Test
  void unchangedFileReturnsCachedResult() throws IOException {
    Path file = tempDir.resolve("Test.java");
    Files.writeString(file, "public class Test {}");

    List<String> findings = List.of("LOW: test finding");
    Map<String, Set<Integer>> taintedParams = Map.of("method", Set.of(0, 1));
    cache.cacheResult(file, tempDir, findings, taintedParams);

    Optional<AnalysisCache.CachedResult> cached = cache.getCachedResult(file, tempDir);
    assertTrue(cached.isPresent());
    assertEquals(1, cached.get().findings().size());
    assertEquals("LOW: test finding", cached.get().findings().get(0));
    assertTrue(cached.get().taintedParams().containsKey("method"));
  }

  @Test
  void changedFileReturnsEmpty() throws IOException {
    Path file = tempDir.resolve("Test.java");
    Files.writeString(file, "public class Test {}");
    cache.cacheResult(file, tempDir, List.of("LOW: finding"), Map.of());

    Files.writeString(file, "public class Test { public void changed() {} }");

    Optional<AnalysisCache.CachedResult> cached = cache.getCachedResult(file, tempDir);
    assertTrue(cached.isEmpty());
  }

  @Test
  void isFileChangedReturnsTrueForNewFile() throws IOException {
    Path file = tempDir.resolve("New.java");
    Files.writeString(file, "public class New {}");
    assertTrue(cache.isFileChanged(file, tempDir));
  }

  @Test
  void isFileChangedReturnsFalseAfterCache() throws IOException {
    Path file = tempDir.resolve("Test.java");
    Files.writeString(file, "public class Test {}");
    cache.cacheResult(file, tempDir, List.of(), Map.of());
    assertFalse(cache.isFileChanged(file, tempDir));
  }

  @Test
  void invalidateRemovesEntry() throws IOException {
    Path file = tempDir.resolve("Test.java");
    Files.writeString(file, "public class Test {}");
    cache.cacheResult(file, tempDir, List.of("finding"), Map.of());

    cache.invalidate(file, tempDir);

    Optional<AnalysisCache.CachedResult> cached = cache.getCachedResult(file, tempDir);
    assertTrue(cached.isEmpty());
  }

  @Test
  void clearRemovesAllEntries() throws IOException {
    Path file1 = tempDir.resolve("A.java");
    Path file2 = tempDir.resolve("B.java");
    Files.writeString(file1, "public class A {}");
    Files.writeString(file2, "public class B {}");
    cache.cacheResult(file1, tempDir, List.of(), Map.of());
    cache.cacheResult(file2, tempDir, List.of(), Map.of());

    cache.clear();

    assertEquals(0, cache.getStats().get("totalFiles"));
  }

  @Test
  void saveAndLoadPreservesData() throws IOException {
    Path file = tempDir.resolve("Test.java");
    Files.writeString(file, "public class Test {}");
    cache.cacheResult(file, tempDir, List.of("CRITICAL: find"), Map.of("sig", Set.of(0)));

    Path cacheFile = tempDir.resolve("cache.json");
    cache.save(cacheFile);

    AnalysisCache loaded = AnalysisCache.load(cacheFile);
    assertFalse(loaded.isFileChanged(file, tempDir));
    Optional<AnalysisCache.CachedResult> cached = loaded.getCachedResult(file, tempDir);
    assertTrue(cached.isPresent());
    assertEquals(1, cached.get().findings().size());
  }

  @Test
  void loadFromMissingFileReturnsNewCache() throws IOException {
    Path missingCache = tempDir.resolve("nonexistent.json");
    AnalysisCache loaded = AnalysisCache.load(missingCache);
    assertNotNull(loaded);
    assertEquals(0, loaded.getStats().get("totalFiles"));
  }

  @Test
  void getCachedResultReturnsEmptyForUncachedFile() throws IOException {
    Path file = tempDir.resolve("Uncached.java");
    Files.writeString(file, "public class Uncached {}");
    Optional<AnalysisCache.CachedResult> cached = cache.getCachedResult(file, tempDir);
    assertTrue(cached.isEmpty());
  }
}
