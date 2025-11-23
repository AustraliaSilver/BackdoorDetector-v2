package backdoordetected.analyzers;

import org.json.JSONArray;
import org.json.JSONObject;
import backdoordetected.utils.StandaloneLogger;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.*;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public class DependencyAnalyzer {
    private static final Logger logger = StandaloneLogger.getLogger();

    private static final Pattern POM_PROPERTIES_PATTERN = Pattern.compile(
            "META-INF/maven/([^/]+)/([^/]+)/pom\\.properties");

    private static final String OSV_API_URL = "https://api.osv.dev/v1/query";

    private final HttpClient httpClient;
    private final ExecutorService executor;

    public DependencyAnalyzer() {
        this.httpClient = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();

        int threadCount = Math.min(Runtime.getRuntime().availableProcessors(), 10);
        this.executor = Executors.newFixedThreadPool(threadCount,
                new ThreadFactory() {
                    private int count = 0;

                    @Override
                    public Thread newThread(Runnable r) {
                        Thread t = new Thread(r, "OSV-Query-Worker-" + (++count));
                        t.setDaemon(true);
                        return t;
                    }
                });
        logger.info("Initialized async OSV analyzer with " + threadCount + " worker threads.");
    }

    public record Dependency(String groupId, String artifactId, String version) {
    }

    public void analyze(Path pluginPath) {
        logger.info("Analyzing dependencies for: " + pluginPath.getFileName());
        List<Dependency> dependencies = findDependencies(pluginPath);

        if (dependencies.isEmpty()) {
            logger.info("No shaded dependencies found in standard Maven locations.");
            return;
        }

        logger.info("Found " + dependencies.size() + " dependencies. Querying OSV.dev asynchronously...");

        List<CompletableFuture<Boolean>> futures = new ArrayList<>();

        for (Dependency dep : dependencies) {
            CompletableFuture<Boolean> future = queryOsvAsync(dep);
            futures.add(future);
        }

        CompletableFuture<Void> allDone = CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]));
        try {
            allDone.get(5, TimeUnit.MINUTES);
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            logger.log(java.util.logging.Level.SEVERE, "Dependency analysis timed out or failed.", e);
            Thread.currentThread().interrupt();
        }

        long vulnerableCount = futures.stream()
                .mapToLong(f -> f.join() ? 1 : 0)
                .sum();

        if (vulnerableCount == 0) {
            logger.info("No known vulnerabilities found in discovered dependencies.");
        } else {
            logger.warning("Found " + vulnerableCount + " vulnerable dependencies.");
        }

        shutdownExecutor();
    }

    private CompletableFuture<Boolean> queryOsvAsync(Dependency dep) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                return queryOsvSync(dep);
            } catch (Exception e) {
                logger.severe("Async query failed for " + dep + ": " + e.getMessage());
                return false;
            }
        }, executor);
    }

    private boolean queryOsvSync(Dependency dep) throws IOException, InterruptedException {
        JSONObject requestBody = new JSONObject();
        JSONObject pkg = new JSONObject();
        pkg.put("name", dep.artifactId());
        pkg.put("ecosystem", "Maven");
        requestBody.put("package", pkg);
        requestBody.put("version", dep.version());

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(OSV_API_URL))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(requestBody.toString()))
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() == 200) {
            JSONObject json = new JSONObject(response.body());
            JSONArray vulns = json.optJSONArray("vulns");

            if (vulns != null && vulns.length() > 0) {
                logger.warning(
                        "VULNERABLE DEPENDENCY: " + dep.groupId() + ":" + dep.artifactId() + ":" + dep.version());
                for (int i = 0; i < vulns.length(); i++) {
                    JSONObject vuln = vulns.getJSONObject(i);
                    String id = vuln.optString("id", "Unknown");
                    String summary = vuln.has("summary") ? vuln.getString("summary") : "(No summary)";
                    String link = "https://osv.dev/vulnerability/" + id;
                    logger.warning("  - ID: " + id + " | Link: " + link);
                    logger.warning("    Summary: " + summary);
                }
                return true;
            }
        } else if (response.statusCode() != 404) {
            logger.warning("HTTP " + response.statusCode() + " for " + dep);
        }
        return false;
    }

    private List<Dependency> findDependencies(Path pluginPath) {
        List<Dependency> deps = new ArrayList<>();
        try (InputStream fis = Files.newInputStream(pluginPath);
                ZipInputStream zis = new ZipInputStream(fis)) {

            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                if (entry.isDirectory())
                    continue;

                Matcher m = POM_PROPERTIES_PATTERN.matcher(entry.getName());
                if (m.matches()) {
                    String groupId = m.group(1);
                    String artifactId = m.group(2);

                    Properties props = new Properties();
                    props.load(zis);
                    String version = props.getProperty("version");

                    if (version != null && !version.isBlank()) {
                        deps.add(new Dependency(groupId, artifactId, version.trim()));
                    }
                }
                zis.closeEntry();
            }
        } catch (IOException e) {
            logger.severe("Error reading JAR: " + e.getMessage());
        }
        return deps;
    }

    private void shutdownExecutor() {
        executor.shutdown();
        try {
            if (!executor.awaitTermination(10, TimeUnit.SECONDS)) {
                executor.shutdownNow();
            }
        } catch (InterruptedException e) {
            executor.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }
}