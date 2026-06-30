package backdoordetected.services;

import backdoordetected.models.BackendAnalysisResult;
import backdoordetected.models.ComprehensiveAnalysisResult;
import backdoordetected.utils.StandaloneLogger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Base64;
import java.util.List;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

import org.json.JSONArray;
import org.json.JSONObject;

public class BackendAnalysisService {
  private static final Logger logger = StandaloneLogger.getLogger();
  private static final Duration TIMEOUT = Duration.ofSeconds(120);
  private static final Duration KEY_FETCH_TIMEOUT = Duration.ofSeconds(10);
  private static final Duration CHALLENGE_TIMEOUT = Duration.ofSeconds(5);

  private static PublicKey cachedPublicKey = null;
  private static String cachedFingerprint = null;

  private static final String BACKEND_URL = "http://93.115.101.157:13384";
  private static final String PINNED_FINGERPRINT = "14d709fbca96e35dc6a9e0a15dca5fa321c93677440c381a4a4a315e20fd82d8";

  private final String backendUrl;
  private final HttpClient httpClient;
  private final boolean forceEncrypt;

  public BackendAnalysisService() {
    this(true);
  }

  public BackendAnalysisService(String backendUrl) {
    this(true);
  }

  public BackendAnalysisService(boolean forceEncrypt) {
    this.backendUrl = BACKEND_URL;
    this.httpClient = HttpClient.newHttpClient();
    this.forceEncrypt = forceEncrypt;
  }

  public BackendAnalysisService(String backendUrl, boolean forceEncrypt) {
    this(forceEncrypt);
  }

  private boolean verifyFingerprint(String pem) {
    if (pem == null) return false;
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      byte[] hash = digest.digest(pem.getBytes(StandardCharsets.UTF_8));
      StringBuilder sb = new StringBuilder();
      for (byte b : hash) {
        sb.append(String.format("%02x", b));
      }
      String computed = sb.toString();
      logger.info("[crypto] Computed fingerprint: " + computed);
      logger.info("[crypto] Pinned fingerprint:   " + PINNED_FINGERPRINT);
      return computed.equalsIgnoreCase(PINNED_FINGERPRINT);
    } catch (Exception e) {
      logger.severe("[crypto] Fingerprint verification error: " + e.getMessage());
      return false;
    }
  }

  private PublicKey getPublicKey() {
    if (cachedPublicKey != null) return cachedPublicKey;
    try {
      HttpRequest req = HttpRequest.newBuilder()
          .uri(URI.create(backendUrl + "/api/public-key"))
          .timeout(KEY_FETCH_TIMEOUT)
          .GET()
          .build();
      HttpResponse<String> res = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
      if (res.statusCode() != 200) {
        throw new RuntimeException("Failed to fetch public key: HTTP " + res.statusCode());
      }
      JSONObject json = new JSONObject(res.body());
      String pem = json.getString("publicKey");
      if (!verifyFingerprint(pem)) {
        throw new SecurityException("CRITICAL: Backend public key fingerprint mismatch! Network might be hijacked!");
      }
      cachedFingerprint = json.optString("fingerprint", "");
      cachedPublicKey = parsePemPublicKey(pem);
      logger.info("[crypto] Fetched RSA public key, fingerprint: " + cachedFingerprint);
      return cachedPublicKey;
    } catch (Exception e) {
      logger.severe("[crypto] Failed to fetch public key: " + e.getMessage());
      return null;
    }
  }

  private static PublicKey parsePemPublicKey(String pem) {
    try {
      String b64 = pem
          .replace("-----BEGIN PUBLIC KEY-----", "")
          .replace("-----END PUBLIC KEY-----", "")
          .replaceAll("\\s", "");
      byte[] der = Base64.getDecoder().decode(b64);
      X509EncodedKeySpec spec = new X509EncodedKeySpec(der);
      KeyFactory kf = KeyFactory.getInstance("RSA");
      return kf.generatePublic(spec);
    } catch (Exception e) {
      throw new RuntimeException("Failed to parse PEM public key", e);
    }
  }

  private JSONObject decryptResponse(String bodyStr, SecretKey aesKey) throws Exception {
    JSONObject obj = new JSONObject(bodyStr);
    byte[] encryptedData = Base64.getDecoder().decode(obj.getString("encryptedData"));
    byte[] iv = Base64.getDecoder().decode(obj.getString("iv"));
    byte[] tag = Base64.getDecoder().decode(obj.getString("tag"));

    byte[] ciphertext = new byte[encryptedData.length + tag.length];
    System.arraycopy(encryptedData, 0, ciphertext, 0, encryptedData.length);
    System.arraycopy(tag, 0, ciphertext, encryptedData.length, tag.length);

    Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
    GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
    aesCipher.init(Cipher.DECRYPT_MODE, aesKey, gcmSpec);
    byte[] plaintext = aesCipher.doFinal(ciphertext);

    return new JSONObject(new String(plaintext, StandardCharsets.UTF_8));
  }

  public BackendAnalysisResult analyze(Path pluginPath, ComprehensiveAnalysisResult analysis, String workerName) {
    try {
      JSONObject payload = buildPayload(pluginPath, analysis);
      String jsonBody = payload.toString();

      String[] challenge = fetchChallenge();
      if (challenge == null) {
        logger.severe("[" + workerName + "] Failed to get PoW challenge from backend");
        return null;
      }
      String challengeStr = challenge[0];
      int difficulty = Integer.parseInt(challenge[1]);

      logger.info("[" + workerName + "] Solving PoW (difficulty=" + difficulty + ")...");
      long solveStart = System.nanoTime();
      String nonce = solvePow(challengeStr, difficulty);
      long solveElapsed = (System.nanoTime() - solveStart) / 1_000_000;
      logger.info("[" + workerName + "] PoW solved in " + solveElapsed + "ms, nonce=" + nonce);

      HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
          .uri(URI.create(backendUrl + "/api/analyze"))
          .timeout(TIMEOUT)
          .header("X-Challenge", challengeStr)
          .header("X-Nonce", nonce);

      boolean useEncryption = forceEncrypt && getPublicKey() != null;
      SecretKey aesKey = null;

      if (useEncryption) {
        EncryptedPayloadAndKey encResult = encryptPayloadAndKey(jsonBody);
        EncryptedPayload encrypted = encResult.payload;
        aesKey = encResult.aesKey;
        String encBody = encrypted.toJson().toString();
        logger.info("[" + workerName + "] Sending encrypted analysis to AI backend at "
            + backendUrl + " (plain " + jsonBody.length()
            + "b -> encrypted " + encBody.length() + "b)");
        requestBuilder
            .header("Content-Type", "application/json")
            .header("X-Encrypted", "hybrid")
            .POST(HttpRequest.BodyPublishers.ofString(encBody));
      } else {
        logger.info("[" + workerName + "] Sending analysis to AI backend at "
            + backendUrl + " (" + jsonBody.length() + " bytes)");
        requestBuilder
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(jsonBody));
      }

      HttpResponse<String> response = httpClient.send(requestBuilder.build(), HttpResponse.BodyHandlers.ofString());

      if (response.statusCode() == 403) {
        JSONObject err = new JSONObject(response.body());
        String newChallenge = err.optString("challenge", "");
        int newDiff = err.optInt("difficulty", difficulty);
        if (!newChallenge.isEmpty()) {
          logger.info("[" + workerName + "] PoW challenge expired, re-solving (difficulty=" + newDiff + ")...");
          String newNonce = solvePow(newChallenge, newDiff);
          requestBuilder.setHeader("X-Challenge", newChallenge);
          requestBuilder.setHeader("X-Nonce", newNonce);
          response = httpClient.send(requestBuilder.build(), HttpResponse.BodyHandlers.ofString());
        } else {
          logger.severe("[" + workerName + "] Backend rejected request: " + err.optString("error", "unknown"));
          return null;
        }
      }

      if (response.statusCode() != 200) {
        logger.severe("[" + workerName + "] Backend HTTP " + response.statusCode()
            + ": " + response.body());
        return null;
      }

      JSONObject json = new JSONObject(response.body());
      if (useEncryption && response.headers().firstValue("X-Encrypted").orElse("").equals("hybrid")) {
        try {
          json = decryptResponse(response.body(), aesKey);
        } catch (Exception e) {
          logger.severe("[" + workerName + "] Failed to decrypt response: " + e.getMessage());
          return null;
        }
      }
      return parseResponse(json);

    } catch (Exception e) {
      logger.severe("[" + workerName + "] Backend call failed: " + e.getMessage());
      return null;
    }
  }

  private String[] fetchChallenge() {
    try {
      HttpRequest req = HttpRequest.newBuilder()
          .uri(URI.create(backendUrl + "/api/challenge"))
          .timeout(CHALLENGE_TIMEOUT)
          .GET()
          .build();
      HttpResponse<String> res = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
      if (res.statusCode() != 200) return null;
      JSONObject json = new JSONObject(res.body());
      return new String[]{
          json.getString("challenge"),
          String.valueOf(json.getInt("difficulty"))
      };
    } catch (Exception e) {
      return null;
    }
  }

  static String solvePow(String challenge, int difficulty) {
    MessageDigest md;
    try {
      md = MessageDigest.getInstance("SHA-256");
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
    byte[] challengeBytes = challenge.getBytes(StandardCharsets.UTF_8);
    long nonce = 0;
    byte[] hashBuf = new byte[32];
    while (true) {
      md.reset();
      md.update(challengeBytes);
      String nonceStr = Long.toHexString(nonce);
      md.update(nonceStr.getBytes(StandardCharsets.UTF_8));
      byte[] hash = md.digest();
      boolean valid = true;
      for (int i = 0; i < difficulty; i++) {
        if (hash[i] != 0) { valid = false; break; }
      }
      if (valid) return nonceStr;
      nonce++;
      if (nonce < 0) nonce = 0;
    }
  }

  private static class EncryptedPayloadAndKey {
    final EncryptedPayload payload;
    final SecretKey aesKey;
    EncryptedPayloadAndKey(EncryptedPayload payload, SecretKey aesKey) {
      this.payload = payload;
      this.aesKey = aesKey;
    }
  }

  private EncryptedPayloadAndKey encryptPayloadAndKey(String plaintext) throws Exception {
    PublicKey pubKey = getPublicKey();
    if (pubKey == null) throw new RuntimeException("No public key available");

    SecureRandom rng = new SecureRandom();

    KeyGenerator kg = KeyGenerator.getInstance("AES");
    kg.init(256, rng);
    SecretKey aesKey = kg.generateKey();

    byte[] iv = new byte[12];
    rng.nextBytes(iv);

    Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
    GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
    aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, gcmSpec);
    byte[] ciphertext = aesCipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

    int tagLen = 16;
    byte[] encryptedData = new byte[ciphertext.length - tagLen];
    byte[] tag = new byte[tagLen];
    System.arraycopy(ciphertext, 0, encryptedData, 0, encryptedData.length);
    System.arraycopy(ciphertext, encryptedData.length, tag, 0, tagLen);

    Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
    rsaCipher.init(Cipher.ENCRYPT_MODE, pubKey);
    byte[] encryptedKey = rsaCipher.doFinal(aesKey.getEncoded());

    EncryptedPayload payload = new EncryptedPayload(
        Base64.getEncoder().encodeToString(encryptedKey),
        Base64.getEncoder().encodeToString(encryptedData),
        Base64.getEncoder().encodeToString(iv),
        Base64.getEncoder().encodeToString(tag),
        String.valueOf(System.currentTimeMillis())
    );
    return new EncryptedPayloadAndKey(payload, aesKey);
  }

  private JSONObject buildPayload(Path pluginPath, ComprehensiveAnalysisResult analysis) throws Exception {
    JSONObject payload = new JSONObject();
    payload.put("clientVersion", backdoordetected.Main.VERSION);
    payload.put("jarName", pluginPath.getFileName().toString());
    payload.put("jarHash", computeSha256(pluginPath));
    payload.put("directoryTree", analysis.directoryTree() != null ? analysis.directoryTree() : "");

    Path bytecodeKey = Path.of("BYTECODE_ANALYSIS");
    List<String> bcFindings = analysis.eventFindings().getOrDefault(bytecodeKey, List.of());
    payload.put("bytecodeFindings", new JSONArray(bcFindings));

    Path sootKey = Path.of("SOOT_ANALYSIS");
    List<String> sootFindings = analysis.eventFindings().getOrDefault(sootKey, List.of());
    payload.put("sootFindings", new JSONArray(sootFindings));

    payload.put("obfuscationScore", analysis.obfuscationResult().score());

    JSONObject suspiciousFiles = new JSONObject();
    for (Path file : analysis.suspiciousFiles()) {
      if (Files.exists(file)) {
        String content = Files.readString(file, StandardCharsets.UTF_8);
        if (content.length() > 100_000) {
          content = content.substring(0, 100_000);
        }
        suspiciousFiles.put(file.getFileName().toString(), content);
      }
    }
    payload.put("suspiciousFiles", suspiciousFiles);
    String codeHash = computeCodeHash(suspiciousFiles);
    if (codeHash != null) {
      payload.put("codeHash", codeHash);
    }

    return payload;
  }

  private BackendAnalysisResult parseResponse(JSONObject json) {
    List<String> indicators = new ArrayList<>();
    if (json.has("keyIndicators") && !json.isNull("keyIndicators")) {
      JSONArray arr = json.getJSONArray("keyIndicators");
      for (int i = 0; i < arr.length(); i++) {
        indicators.add(arr.getString(i));
      }
    }

    return new BackendAnalysisResult(
        json.optBoolean("isMalicious", false),
        json.optString("confidence", "low"),
        json.optString("threatType", "none"),
        json.optString("summary", ""),
        json.optString("analysis", ""),
        indicators,
        json.optInt("riskScore", 0),
        json.optBoolean("cached", false),
        json.optLong("elapsed", 0));
  }

  private String computeSha256(Path filePath) {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      byte[] fileBytes = Files.readAllBytes(filePath);
      byte[] hashBytes = digest.digest(fileBytes);
      StringBuilder sb = new StringBuilder();
      for (byte b : hashBytes) {
        sb.append(String.format("%02x", b));
      }
      return sb.toString();
    } catch (Exception e) {
      return "unknown";
    }
  }

  private String computeCodeHash(JSONObject suspiciousFiles) {
    if (suspiciousFiles == null || suspiciousFiles.isEmpty()) {
      return null;
    }
    try {
      List<String> keys = new ArrayList<>(suspiciousFiles.keySet());
      Collections.sort(keys);
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      for (String key : keys) {
        digest.update((key + ":" + suspiciousFiles.getString(key)).getBytes(StandardCharsets.UTF_8));
      }
      byte[] hash = digest.digest();
      StringBuilder sb = new StringBuilder();
      for (byte b : hash) sb.append(String.format("%02x", b));
      return sb.toString();
    } catch (Exception e) {
      return null;
    }
  }

  private static class EncryptedPayload {
    final String encryptedKey;
    final String encryptedData;
    final String iv;
    final String tag;
    final String timestamp;

    EncryptedPayload(String encryptedKey, String encryptedData, String iv, String tag, String timestamp) {
      this.encryptedKey = encryptedKey;
      this.encryptedData = encryptedData;
      this.iv = iv;
      this.tag = tag;
      this.timestamp = timestamp;
    }

    JSONObject toJson() {
      JSONObject obj = new JSONObject();
      obj.put("encryptedKey", encryptedKey);
      obj.put("encryptedData", encryptedData);
      obj.put("iv", iv);
      obj.put("tag", tag);
      obj.put("timestamp", timestamp);
      return obj;
    }
  }
}
