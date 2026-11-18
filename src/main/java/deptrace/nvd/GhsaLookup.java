package deptrace.nvd;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * CVE에 대응하는 GitHub 권고(GHSA)가 검토됐는지, 검토됐다면 어느 Maven 패키지에 연결됐는지 조회한다.
 * OSV의 Maven 데이터는 GitHub이 검토한 권고에서 온다. 그래서 "검토됐는데 OSV가 보고하지 않았다"면
 * 검토 결과상 해당 모듈·버전이 아니라는 뜻이고, "미검토"면 OSV가 아직 볼 수 없는 공백이다.
 */
public final class GhsaLookup {

    public enum Review { REVIEWED, UNREVIEWED, NONE, UNKNOWN }

    /** mavenPackages: 검토된 권고가 연결한 Maven 패키지(group:artifact). */
    public record Status(Review review, String ghsaId, List<String> mavenPackages) {

        public static final Status UNKNOWN = new Status(Review.UNKNOWN, null, List.of());
    }

    /** 테스트에서 고정 데이터로 바꿀 수 있게 함수로 둔다. */
    public interface Source {
        Status status(String cve);
    }

    private static final Duration TTL = Duration.ofDays(1);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(15)).build();
    private final Path cacheDir;
    private final String token;

    /** token: GITHUB_TOKEN (없으면 시간당 60회로 제한된다). */
    public GhsaLookup(Path cacheDir, String token) {
        this.cacheDir = cacheDir;
        this.token = token == null || token.isBlank() ? null : token.strip();
    }

    public Source source() {
        return this::status;
    }

    public Status status(String cve) {
        Path file = cacheDir.resolve(cve + ".json");
        try {
            JsonNode body;
            if (Files.exists(file) && Files.getLastModifiedTime(file).toInstant().isAfter(Instant.now().minus(TTL))) {
                body = MAPPER.readTree(file.toFile());
            } else {
                HttpRequest.Builder b = HttpRequest.newBuilder(URI.create("https://api.github.com/advisories?cve_id=" + cve))
                        .timeout(Duration.ofSeconds(30)).header("Accept", "application/vnd.github+json")
                        .header("User-Agent", "deptrace");
                if (token != null) {
                    b.header("Authorization", "Bearer " + token);
                }
                HttpResponse<String> r = http.send(b.build(), HttpResponse.BodyHandlers.ofString());
                if (r.statusCode() != 200) {
                    return Status.UNKNOWN;
                }
                body = MAPPER.readTree(r.body());
                Files.createDirectories(cacheDir);
                Files.writeString(file, r.body());
            }
            return parse(body);
        } catch (IOException e) {
            return Status.UNKNOWN;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return Status.UNKNOWN;
        }
    }

    static Status parse(JsonNode advisories) {
        if (!advisories.isArray() || advisories.isEmpty()) {
            return new Status(Review.NONE, null, List.of());
        }
        // 같은 CVE에 권고가 여럿이면 검토된 것을 우선한다
        JsonNode chosen = advisories.get(0);
        for (JsonNode a : advisories) {
            if ("reviewed".equals(a.path("type").asText())) {
                chosen = a;
                break;
            }
        }
        List<String> maven = new ArrayList<>();
        for (JsonNode v : chosen.path("vulnerabilities")) {
            if ("maven".equals(v.path("package").path("ecosystem").asText())) {
                maven.add(v.path("package").path("name").asText());
            }
        }
        Review review = "reviewed".equals(chosen.path("type").asText()) ? Review.REVIEWED : Review.UNREVIEWED;
        return new Status(review, chosen.path("ghsa_id").asText(null), List.copyOf(maven));
    }
}
