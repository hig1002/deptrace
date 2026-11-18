package deptrace.nvd;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * NVD CVE API 2.0에서 제품(vendor:product)에 걸린 CVE를 모두 받는다. 제품 단위로 하루 동안 파일 캐시한다.
 *
 * <p>API 키(NVD_API_KEY)가 있으면 30초에 50회, 없으면 5회까지 허용된다. 키가 없으면 요청 사이에 6초를 쉰다.
 */
public final class NvdClient {

    /** 제품 하나에 걸린 CVE 목록을 주는 출처. 테스트에서는 고정 데이터로 바꾼다. */
    public interface Source {
        List<NvdCve> cves(String vendorProduct);
    }

    private static final String BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0";
    private static final int PAGE = 2000;
    private static final Duration TTL = Duration.ofDays(1);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(15)).build();
    private final Path cacheDir;
    private final String apiKey;
    private int requests;
    private int cached;

    public NvdClient(Path cacheDir, String apiKey) {
        this.cacheDir = cacheDir;
        this.apiKey = apiKey == null || apiKey.isBlank() ? null : apiKey.strip();
    }

    public Source source() {
        return this::cves;
    }

    public String stats() {
        return "NVD 요청 " + requests + "건, 캐시 사용 " + cached + "건" + (apiKey == null ? " (API 키 없음: 느린 속도 제한)" : "");
    }

    public List<NvdCve> cves(String vendorProduct) {
        Path file = cacheDir.resolve(vendorProduct.replaceAll("[^A-Za-z0-9_.-]", "_") + ".json");
        try {
            JsonNode all;
            if (Files.exists(file) && Files.getLastModifiedTime(file).toInstant().isAfter(Instant.now().minus(TTL))) {
                all = MAPPER.readTree(file.toFile());
                cached++;
            } else {
                all = fetchAll(vendorProduct);
                Files.createDirectories(cacheDir);
                MAPPER.writeValue(file.toFile(), all);
            }
            List<NvdCve> out = new ArrayList<>();
            all.forEach(v -> out.add(NvdCve.from(v.path("cve"))));
            return out;
        } catch (IOException e) {
            throw new IllegalStateException("NVD 조회 실패 (" + vendorProduct + "): " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }

    private JsonNode fetchAll(String vendorProduct) throws IOException, InterruptedException {
        var all = MAPPER.createArrayNode();
        int start = 0;
        int total;
        do {
            // CPE 표기 안의 "\/"는 그대로 보내야 NVD가 같은 제품으로 인식한다
            String match = URLEncoder.encode("cpe:2.3:a:" + vendorProduct, StandardCharsets.UTF_8);
            URI uri = URI.create(BASE + "?virtualMatchString=" + match + "&resultsPerPage=" + PAGE + "&startIndex=" + start);
            JsonNode page = get(uri);
            page.path("vulnerabilities").forEach(all::add);
            total = page.path("totalResults").asInt(0);
            start += page.path("resultsPerPage").asInt(PAGE);
        } while (start < total);
        return all;
    }

    private JsonNode get(URI uri) throws IOException, InterruptedException {
        for (int attempt = 1; ; attempt++) {
            if (apiKey == null && requests > 0) {
                Thread.sleep(6_000);
            }
            HttpRequest.Builder b = HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(60)).GET();
            if (apiKey != null) {
                b.header("apiKey", apiKey);
            }
            HttpResponse<String> r = http.send(b.build(), HttpResponse.BodyHandlers.ofString());
            requests++;
            if (r.statusCode() == 200) {
                return MAPPER.readTree(r.body());
            }
            // 403(속도 제한)·503(일시 장애)은 NVD에서 흔하다. 잠시 쉬고 다시 시도한다
            if ((r.statusCode() == 403 || r.statusCode() >= 500) && attempt < 4) {
                Thread.sleep(10_000L * attempt);
                continue;
            }
            throw new IOException("HTTP " + r.statusCode());
        }
    }
}
