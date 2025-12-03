package backdoordetected.cache;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

public class AnalysisCache {
  public static class CachedResult {
    private final List<String> findings;
    private final Map<String, Set<Integer>> taintedParams;

    public CachedResult(List<String> findings, Map<String, Set<Integer>> taintedParams) {
      this.findings = findings;
      this.taintedParams = taintedParams;
    }

    public List<String> findings() {
      return findings;
    }

    public Map<String, Set<Integer>> taintedParams() {
      return taintedParams;
    }
  }

  private final Map<String, String> fileHashes;
  private final Map<String, List<String>> cachedFindings;
  private final Map<String, Map<String, Set<Integer>>> cachedTaintedParams;
  private final Gson gson;

  public AnalysisCache() {
    this.fileHashes = new HashMap<>();
    this.cachedFindings = new HashMap<>();
    this.cachedTaintedParams = new HashMap<>();
    this.gson = new GsonBuilder().setPrettyPrinting().create();
  }

  private String computeFileHash(Path file) throws IOException {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      byte[] fileBytes = Files.readAllBytes(file);
      byte[] hashBytes = digest.digest(fileBytes);
      StringBuilder hexString = new StringBuilder();
      for (byte b : hashBytes) {
        String hex = Integer.toHexString(0xff & b);
        if (hex.length() == 1) hexString.append('0');
        hexString.append(hex);
      }
      return hexString.toString();
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException("SHA-256 algorithm not available", e);
    }
  }

  public boolean isFileChanged(Path file, Path workingDir) throws IOException {
    String relativePath = workingDir.relativize(file).toString();
    String currentHash = computeFileHash(file);
    String cachedHash = fileHashes.get(relativePath);

    return cachedHash == null || !cachedHash.equals(currentHash);
  }

  public void updateFileHash(Path file, Path workingDir) throws IOException {
    String relativePath = workingDir.relativize(file).toString();
    String hash = computeFileHash(file);
    fileHashes.put(relativePath, hash);
  }

  public void cacheResult(
      Path file, Path workingDir, List<String> findings, Map<String, Set<Integer>> taintedParams)
      throws IOException {
    String relativePath = workingDir.relativize(file).toString();
    updateFileHash(file, workingDir);
    cachedFindings.put(relativePath, new ArrayList<>(findings));
    Map<String, Set<Integer>> paramsCopy = new HashMap<>();
    taintedParams.forEach((sig, indices) -> paramsCopy.put(sig, new HashSet<>(indices)));
    cachedTaintedParams.put(relativePath, paramsCopy);
  }

  public Optional<CachedResult> getCachedResult(Path file, Path workingDir) throws IOException {
    if (isFileChanged(file, workingDir)) {
      return Optional.empty();
    }
    String relativePath = workingDir.relativize(file).toString();
    List<String> findings = cachedFindings.get(relativePath);
    Map<String, Set<Integer>> taintedParams = cachedTaintedParams.get(relativePath);
    if (findings == null) {
      return Optional.empty();
    }

    return Optional.of(
        new CachedResult(findings, taintedParams != null ? taintedParams : new HashMap<>()));
  }

  public void invalidate(Path file, Path workingDir) {
    String relativePath = workingDir.relativize(file).toString();
    fileHashes.remove(relativePath);
    cachedFindings.remove(relativePath);
    cachedTaintedParams.remove(relativePath);
  }

  public void clear() {
    fileHashes.clear();
    cachedFindings.clear();
    cachedTaintedParams.clear();
  }

  public void save(Path cacheFile) throws IOException {
    Files.createDirectories(cacheFile.getParent());

    Map<String, Object> cacheData = new HashMap<>();
    cacheData.put("fileHashes", fileHashes);
    cacheData.put("cachedFindings", cachedFindings);
    cacheData.put("cachedTaintedParams", cachedTaintedParams);

    String json = gson.toJson(cacheData);
    Files.writeString(cacheFile, json);
  }

  public static AnalysisCache load(Path cacheFile) throws IOException {
    if (!Files.exists(cacheFile)) {
      return new AnalysisCache();
    }

    String json = Files.readString(cacheFile);
    Gson gson = new Gson();

    Map<String, Object> cacheData =
        gson.fromJson(json, new TypeToken<Map<String, Object>>() {}.getType());

    AnalysisCache cache = new AnalysisCache();

    if (cacheData.containsKey("fileHashes")) {
      Map<String, String> hashes =
          gson.fromJson(
              gson.toJson(cacheData.get("fileHashes")),
              new TypeToken<Map<String, String>>() {}.getType());
      cache.fileHashes.putAll(hashes);
    }

    if (cacheData.containsKey("cachedFindings")) {
      Map<String, List<String>> findings =
          gson.fromJson(
              gson.toJson(cacheData.get("cachedFindings")),
              new TypeToken<Map<String, List<String>>>() {}.getType());
      cache.cachedFindings.putAll(findings);
    }

    if (cacheData.containsKey("cachedTaintedParams")) {
      Map<String, Map<String, Set<Integer>>> params =
          gson.fromJson(
              gson.toJson(cacheData.get("cachedTaintedParams")),
              new TypeToken<Map<String, Map<String, Set<Integer>>>>() {}.getType());
      cache.cachedTaintedParams.putAll(params);
    }

    return cache;
  }

  public Map<String, Integer> getStats() {
    Map<String, Integer> stats = new HashMap<>();
    stats.put("totalFiles", fileHashes.size());
    stats.put("cachedFindings", cachedFindings.size());
    stats.put("cachedMethods", cachedTaintedParams.values().stream().mapToInt(Map::size).sum());
    return stats;
  }
}
