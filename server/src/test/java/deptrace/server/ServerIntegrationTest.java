package deptrace.server;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.TestPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import deptrace.osv.Severity;

/**
 * 실제 PostgreSQL(Testcontainers)에서 업로드 → 발견 → 재검사 → 해결의 흐름을 확인한다.
 * OSV만 고정 데이터로 바꾼다.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Testcontainers
@TestPropertySource(properties = {"deptrace.api-token=test-token", "deptrace.rescan.cron=-"})
class ServerIntegrationTest {

    @Container
    @ServiceConnection
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:17-alpine");

    @TestConfiguration
    static class Config {

        /** FakeOsv는 VulnerabilitySource라서 이 빈 하나로 실제 OSV 클라이언트를 대신한다. */
        @Bean
        @Primary
        FakeOsv fakeOsv() {
            return new FakeOsv();
        }
    }

    private static final String WEBMVC_OLD = "org.springframework:spring-webmvc:6.2.19";
    private static final String WEBMVC_NEW = "org.springframework:spring-webmvc:7.0.9";
    private static final String GUAVA = "com.google.guava:guava:33.6.0-jre";
    private static final String NETTY = "io.netty:netty-codec-http:4.1.138.Final";

    @Autowired
    TestRestTemplate http;

    @Autowired
    FakeOsv osv;

    @Autowired
    JdbcTemplate jdbc;

    @BeforeEach
    void clean() {
        jdbc.execute("update project set current_snapshot_id = null");
        jdbc.execute("delete from finding; delete from component_advisory; delete from advisory_alias; delete from advisory;"
                + " delete from snapshot_component; delete from snapshot; delete from project; delete from component");
        osv.reset();
        // SSE 권고 (경매톡 사례의 GHSA-j9f9-w8pj-32f8 / CVE-2026-47890)
        osv.publish(WEBMVC_OLD, "GHSA-j9f9-w8pj-32f8", "CVE-2026-47890", Severity.CRITICAL);
    }

    @Test
    void 업로드하면_발견이_열리고_같은_SBOM을_다시_올려도_중복되지_않는다() {
        Map<String, Object> first = upload("gyeongmaetalk", WEBMVC_OLD, GUAVA);
        assertThat(first).containsEntry("components", 2).containsEntry("scanned", 2).containsEntry("opened", 1);

        Map<String, Object> again = upload("gyeongmaetalk", WEBMVC_OLD, GUAVA);
        // 24시간 안에 조회한 구성요소는 다시 묻지 않고, 발견도 새로 만들지 않는다
        assertThat(again).containsEntry("scanned", 0).containsEntry("opened", 0).containsEntry("resolved", 0);

        List<Map<String, Object>> findings = getList("/api/projects/gyeongmaetalk/findings?status=OPEN");
        assertThat(findings).singleElement().satisfies(f -> {
            assertThat(f).containsEntry("advisory", "GHSA-j9f9-w8pj-32f8").containsEntry("detectedBy", "UPLOAD");
            assertThat(f.get("aliases").toString()).contains("CVE-2026-47890");
        });
    }

    @Test
    void 프로젝트가_달라도_같은_버전은_한_번만_조회한다() {
        upload("gyeongmaetalk", WEBMVC_OLD, GUAVA);
        osv.clearAsked();

        Map<String, Object> other = upload("other-service", WEBMVC_OLD, NETTY);

        // webmvc는 이미 조회했으니 netty 하나만 묻는다. 발견은 프로젝트별로 생긴다
        assertThat(osv.askedCount()).isEqualTo(1);
        assertThat(other).containsEntry("scanned", 1).containsEntry("opened", 1);
    }

    @Test
    void 코드_변경_없이_새_권고가_공개되면_재검사에서_잡고_다시_돌려도_중복되지_않는다() {
        upload("gyeongmaetalk", WEBMVC_OLD, GUAVA);
        upload("other-service", WEBMVC_OLD, NETTY);
        osv.clearAsked();

        // 점검 이후 공개된 guava 권고 (경매톡 GHSA-xxph-c9ww-hj94 사례)
        osv.publish(GUAVA, "GHSA-xxph-c9ww-hj94", null, Severity.HIGH);
        Map<String, Object> rescan = post("/api/rescan", null, "test-token");

        assertThat(rescan).containsEntry("status", "COMPLETED").containsEntry("newFindings", 1);
        // 두 프로젝트의 구성요소 4개 중 겹치는 webmvc를 빼고 3개만 조회
        assertThat(osv.askedCount()).isEqualTo(3);
        assertThat(getList("/api/projects/gyeongmaetalk/findings?status=OPEN"))
                .anySatisfy(f -> assertThat(f).containsEntry("advisory", "GHSA-xxph-c9ww-hj94").containsEntry("detectedBy", "RESCAN"));

        assertThat(post("/api/rescan", null, "test-token")).containsEntry("newFindings", 0);
    }

    @Test
    void 버전을_올리면_해결되고_CVE로_영향받는_프로젝트를_찾는다() {
        upload("gyeongmaetalk", WEBMVC_OLD, GUAVA);
        upload("other-service", WEBMVC_OLD, NETTY);

        Map<String, Object> impact = get("/api/advisories/CVE-2026-47890/impact");
        assertThat(projectsOf(impact)).containsExactlyInAnyOrder("gyeongmaetalk", "other-service");

        Map<String, Object> upgraded = upload("gyeongmaetalk", WEBMVC_NEW, GUAVA);
        assertThat(upgraded).containsEntry("resolved", 1);
        assertThat(getList("/api/projects/gyeongmaetalk/findings?status=RESOLVED")).hasSize(1);
        assertThat(projectsOf(get("/api/advisories/CVE-2026-47890/impact"))).containsExactly("other-service");

        // 어느 프로젝트가 어떤 버전을 쓰는지 (권고와 무관하게)
        assertThat(get("/api/components/usage?module=org.springframework:spring-webmvc"))
                .containsEntry("gyeongmaetalk", List.of("7.0.9")).containsEntry("other-service", List.of("6.2.19"));
    }

    @Test
    void 권고가_철회되면_재검사에서_해결로_바뀐다() {
        upload("gyeongmaetalk", WEBMVC_OLD, GUAVA);
        osv.withdraw(WEBMVC_OLD, "GHSA-j9f9-w8pj-32f8");

        post("/api/rescan", null, "test-token");

        assertThat(getList("/api/projects/gyeongmaetalk/findings?status=OPEN")).isEmpty();
        assertThat(getList("/api/projects/gyeongmaetalk/findings?status=RESOLVED")).hasSize(1);
    }

    @Test
    void 쓰기_요청은_토큰이_필요하고_읽기는_필요없다() {
        ResponseEntity<String> noToken = http.exchange("/api/projects/x/sboms", HttpMethod.POST,
                new HttpEntity<>(sbom(GUAVA), jsonHeaders(null)), String.class);
        ResponseEntity<String> wrong = http.exchange("/api/rescan", HttpMethod.POST, new HttpEntity<>(null, jsonHeaders("nope")), String.class);

        assertThat(noToken.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(wrong.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(http.getForEntity("/api/projects", String.class).getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void CycloneDX가_아니면_400이다() {
        ResponseEntity<String> r = http.exchange("/api/projects/x/sboms", HttpMethod.POST,
                new HttpEntity<>("{\"hello\":1}", jsonHeaders("test-token")), String.class);

        assertThat(r.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(r.getBody()).contains("CycloneDX");
    }

    // ---- helpers ----

    private static List<String> projectsOf(Map<String, Object> impact) {
        return ((Map<?, ?>) impact.get("projects")).keySet().stream().map(String::valueOf).toList();
    }

    private Map<String, Object> upload(String project, String... coordinates) {
        return post("/api/projects/" + project + "/sboms", sbom(coordinates), "test-token");
    }

    private static String sbom(String... coordinates) {
        StringBuilder components = new StringBuilder();
        for (String c : coordinates) {
            String[] p = c.split(":");
            if (!components.isEmpty()) {
                components.append(',');
            }
            components.append("{\"type\":\"library\",\"purl\":\"pkg:maven/").append(p[0]).append('/').append(p[1])
                    .append('@').append(p[2]).append("\"}");
        }
        return "{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.6\",\"metadata\":{\"tools\":{\"components\":"
                + "[{\"name\":\"deptrace\",\"version\":\"0.1.0\"}]}},\"components\":[" + components + "]}";
    }

    private Map<String, Object> post(String path, String body, String token) {
        ResponseEntity<Map<String, Object>> r = http.exchange(path, HttpMethod.POST, new HttpEntity<>(body, jsonHeaders(token)),
                new ParameterizedTypeReference<>() {
                });
        assertThat(r.getStatusCode().is2xxSuccessful()).as("POST %s → %s", path, r.getStatusCode()).isTrue();
        return r.getBody();
    }

    private Map<String, Object> get(String path) {
        return http.exchange(path, HttpMethod.GET, null, new ParameterizedTypeReference<Map<String, Object>>() {
        }).getBody();
    }

    private List<Map<String, Object>> getList(String path) {
        return http.exchange(path, HttpMethod.GET, null, new ParameterizedTypeReference<List<Map<String, Object>>>() {
        }).getBody();
    }

    private static HttpHeaders jsonHeaders(String token) {
        HttpHeaders h = new HttpHeaders();
        h.setContentType(MediaType.APPLICATION_JSON);
        if (token != null) {
            h.setBearerAuth(token);
        }
        return h;
    }
}
