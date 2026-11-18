package deptrace.osv;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import deptrace.model.Coordinate;

/**
 * OSV API 클라이언트 (https://google.github.io/osv.dev/api/).
 *
 * <p>1) /v1/querybatch로 좌표(purl)별 영향 취약점 ID를 한 번에 조회한다. 배치 조회는 ID와 수정 시각만 돌려준다.
 * 2) 여러 패키지에 걸친 같은 ID는 한 번만 /v1/vulns/{id}로 상세 조회한다.
 * 3) 상세 응답은 "ID@수정시각" 키로 캐시한다. 수정 시각이 바뀌면 새로 받으므로 오래된 데이터를 쓰지 않는다.
 * 영향 여부 조회 자체는 캐시하지 않는다. 새로 공개된 취약점을 놓치지 않기 위해서다.
 */
public final class OsvClient implements VulnerabilitySource {

    private static final URI QUERY_BATCH = URI.create("https://api.osv.dev/v1/querybatch");
    private static final String VULN = "https://api.osv.dev/v1/vulns/";
    private static final int BATCH_LIMIT = 1000;

    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
    private final ObjectMapper json = new ObjectMapper();
    private final Path cacheDir;
    private int detailRequests;
    private int cacheHits;

    public OsvClient(Path cacheDir) {
        this.cacheDir = cacheDir;
    }

    private record Ref(String id, String modified) {
    }

    @Override
    public Map<Coordinate, List<OsvVulnerability>> vulnerabilities(Collection<Coordinate> coordinates) {
        List<Coordinate> list = new ArrayList<>(new LinkedHashSet<>(coordinates));
        Map<Coordinate, List<Ref>> refs = new LinkedHashMap<>();
        for (int i = 0; i < list.size(); i += BATCH_LIMIT) {
            List<Coordinate> chunk = list.subList(i, Math.min(list.size(), i + BATCH_LIMIT));
            refs.putAll(queryBatch(chunk));
        }

        Set<Ref> unique = new LinkedHashSet<>();
        refs.values().forEach(unique::addAll);
        Map<String, OsvVulnerability> details = fetchAll(unique);

        Map<Coordinate, List<OsvVulnerability>> result = new LinkedHashMap<>();
        refs.forEach((coordinate, ids) -> {
            List<OsvVulnerability> vulns = ids.stream().map(r -> details.get(r.id()))
                    .filter(v -> v != null && v.withdrawn() == null).toList();
            if (!vulns.isEmpty()) {
                result.put(coordinate, vulns);
            }
        });
        return result;
    }

    public String stats() {
        return "OSV 상세 조회 " + detailRequests + "건, 캐시 사용 " + cacheHits + "건";
    }

    private Map<Coordinate, List<Ref>> queryBatch(List<Coordinate> chunk) {
        ObjectNode body = json.createObjectNode();
        ArrayNode queries = body.putArray("queries");
        chunk.forEach(c -> queries.addObject().putObject("package").put("purl", c.purl()));

        JsonNode response = post(QUERY_BATCH, body);
        Map<Coordinate, List<Ref>> refs = new LinkedHashMap<>();
        JsonNode results = response.path("results");
        for (int i = 0; i < chunk.size(); i++) {
            JsonNode r = results.path(i);
            if (r.hasNonNull("next_page_token")) {
                System.err.println("경고: " + chunk.get(i) + " 의 결과가 페이지로 나뉘어 일부만 반영됨");
            }
            List<Ref> ids = new ArrayList<>();
            r.path("vulns").forEach(v -> ids.add(new Ref(v.path("id").asText(), v.path("modified").asText(""))));
            if (!ids.isEmpty()) {
                refs.put(chunk.get(i), ids);
            }
        }
        return refs;
    }

    private Map<String, OsvVulnerability> fetchAll(Set<Ref> refs) {
        Map<String, OsvVulnerability> details = new ConcurrentHashMap<>();
        ExecutorService pool = Executors.newFixedThreadPool(8);
        try {
            List<Future<?>> futures = new ArrayList<>();
            for (Ref ref : refs) {
                futures.add(pool.submit(() -> details.put(ref.id(), fetch(ref))));
            }
            for (Future<?> f : futures) {
                f.get();
            }
        } catch (Exception e) {
            throw new IllegalStateException("OSV 상세 조회 실패", e);
        } finally {
            pool.shutdown();
        }
        return details;
    }

    private OsvVulnerability fetch(Ref ref) throws IOException {
        Path cached = cacheDir.resolve((ref.id() + "@" + ref.modified()).replaceAll("[^A-Za-z0-9._@-]", "_") + ".json");
        if (Files.exists(cached)) {
            synchronized (this) {
                cacheHits++;
            }
            return OsvVulnerability.from(json.readTree(cached.toFile()));
        }
        JsonNode node = get(URI.create(VULN + ref.id()));
        synchronized (this) {
            detailRequests++;
        }
        Files.createDirectories(cacheDir);
        json.writeValue(cached.toFile(), node);
        return OsvVulnerability.from(node);
    }

    private JsonNode post(URI uri, JsonNode body) {
        try {
            return send(HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(60))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(json.writeValueAsString(body))).build());
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private JsonNode get(URI uri) {
        return send(HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(30)).GET().build());
    }

    /** 429·5xx는 지수 백오프로 최대 3번 재시도한다. */
    private JsonNode send(HttpRequest request) {
        for (int attempt = 1; ; attempt++) {
            try {
                HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
                int status = response.statusCode();
                if (status == 200) {
                    return json.readTree(response.body());
                }
                if ((status == 429 || status >= 500) && attempt < 3) {
                    Thread.sleep(500L << attempt);
                    continue;
                }
                throw new IllegalStateException("OSV 응답 " + status + ": " + request.uri());
            } catch (IOException e) {
                if (attempt >= 3) {
                    throw new UncheckedIOException(e);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException(e);
            }
        }
    }
}
