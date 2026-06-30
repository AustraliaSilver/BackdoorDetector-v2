package backdoordetected.services;

import static org.junit.jupiter.api.Assertions.*;

import backdoordetected.models.DecompilationResult;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class CacheServiceTest {

  private CacheService cacheService;

  @BeforeEach
  void setUp() {
    cacheService = new CacheService();
  }

  @Test
  void decompilationCacheMissReturnsEmpty() {
    Optional<DecompilationResult> result = cacheService.getDecompilation("nonexistent-hash-long");
    assertTrue(result.isEmpty());
  }

  @Test
  void decompilationCacheHitReturnsCachedValue() {
    DecompilationResult expected = new DecompilationResult(
        List.of(Path.of("Test.java")), Map.of(), Path.of("/tmp"));
    cacheService.putDecompilation("hash12345678", expected);

    Optional<DecompilationResult> result = cacheService.getDecompilation("hash12345678");
    assertTrue(result.isPresent());
    assertSame(expected, result.get());
  }

  @Test
  void aiCacheMissReturnsEmpty() {
    Optional<String> result = cacheService.getAIResult("nonexistent-hash-long");
    assertTrue(result.isEmpty());
  }

  @Test
  void aiCacheHitReturnsCachedValue() {
    cacheService.putAIResult("hash4567890", "AI analysis result");

    Optional<String> result = cacheService.getAIResult("hash4567890");
    assertTrue(result.isPresent());
    assertEquals("AI analysis result", result.get());
  }

  @Test
  void clearAllEmptiesBothCaches() {
    cacheService.putDecompilation("hash1-long", new DecompilationResult(
        List.of(), Map.of(), Path.of("/tmp")));
    cacheService.putAIResult("hash2-long-", "result");

    cacheService.clearAll();

    assertTrue(cacheService.getDecompilation("hash1-long").isEmpty());
    assertTrue(cacheService.getAIResult("hash2-long-").isEmpty());
  }

  @Test
  void decompilationCacheIsIndependentOfAiCache() {
    cacheService.putDecompilation("hash-long-1", new DecompilationResult(
        List.of(), Map.of(), Path.of("/tmp")));
    assertTrue(cacheService.getDecompilation("hash-long-1").isPresent());
    assertTrue(cacheService.getAIResult("hash-long-1").isEmpty());
  }

  @Test
  void overwritingCacheEntryReplacesValue() {
    DecompilationResult first = new DecompilationResult(
        List.of(Path.of("A.java")), Map.of(), Path.of("/tmp"));
    DecompilationResult second = new DecompilationResult(
        List.of(Path.of("B.java")), Map.of(), Path.of("/tmp"));

    cacheService.putDecompilation("hash-long-2", first);
    cacheService.putDecompilation("hash-long-2", second);

    Optional<DecompilationResult> result = cacheService.getDecompilation("hash-long-2");
    assertTrue(result.isPresent());
    assertEquals(List.of(Path.of("B.java")), result.get().javaFiles());
  }
}
