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

import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;

import java.time.Duration;
import java.time.LocalDate;
import java.time.ZoneOffset;

import deptrace.osv.Severity;
import deptrace.server.notify.Notifier;

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

        /** 예외 만료를 확인하려고 시간을 앞으로 보낼 수 있는 시계로 바꾼다. */
        @Bean
        @Primary
        MutableClock mutableClock() {
            return new MutableClock();
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

    @Autowired
    MutableClock clock;

    @MockitoSpyBean
    Notifier notifier;

    @BeforeEach
    void clean() {
        jdbc.execute("update project set current_snapshot_id = null");
        jdbc.execute("delete from finding; delete from risk_acceptance; delete from component_advisory; delete from advisory_alias;"
                + " delete from advisory; delete from snapshot_component; delete from snapshot; delete from project; delete from component");
        osv.reset();
        clock.reset();
        Mockito.clearInvocations(notifier);
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

    // ---- 예외(위험 수용) ----

    private static final String SSE_REASON = "SseEmitter·ServerSentEvent 사용 없음 (src/main 검색 0건)";

    @Test
    void 예외를_등록하면_발견이_수용되고_열린_목록과_영향_조회에서_빠진다() {
        upload("gyeongmaetalk", WEBMVC_OLD, GUAVA);

        // 사람은 보통 CVE 번호로 말한다. GHSA로 저장된 권고를 별칭으로 찾는다
        Map<String, Object> created = createException("gyeongmaetalk", "CVE-2026-47890", "org.springframework:spring-webmvc",
                SSE_REASON, today().plusDays(30));

        assertThat(created).containsEntry("accepted", 1);
        assertThat(getList("/api/projects/gyeongmaetalk/findings?status=OPEN")).isEmpty();
        assertThat(getList("/api/projects/gyeongmaetalk/findings?status=ACCEPTED")).singleElement()
                .satisfies(f -> assertThat(f.get("acceptance").toString()).contains("SseEmitter"));
        assertThat(getList("/api/projects")).singleElement()
                .satisfies(p -> assertThat(p).containsEntry("openBySeverity", Map.of()).containsEntry("accepted", 1));
        assertThat(projectsOf(get("/api/advisories/CVE-2026-47890/impact"))).isEmpty();
    }

    @Test
    void 예외가_만료되면_재검사에서_다시_열리고_알린다() {
        upload("gyeongmaetalk", WEBMVC_OLD, GUAVA);
        createException("gyeongmaetalk", "GHSA-j9f9-w8pj-32f8", null, SSE_REASON, today().plusDays(30));
        Mockito.clearInvocations(notifier);

        // 만료일 당일까지는 유효하다
        clock.advance(Duration.ofDays(30));
        post("/api/rescan", null, "test-token");
        assertThat(getList("/api/projects/gyeongmaetalk/findings?status=ACCEPTED")).hasSize(1);

        clock.advance(Duration.ofDays(1));
        post("/api/rescan", null, "test-token");

        assertThat(getList("/api/projects/gyeongmaetalk/findings?status=OPEN")).singleElement()
                .satisfies(f -> assertThat(f).containsEntry("advisory", "GHSA-j9f9-w8pj-32f8"));
        assertThat(sentAlerts()).anySatisfy(a -> assertThat(a.event()).isEqualTo("ACCEPTANCE_ENDED"));
        assertThat(getList("/api/projects/gyeongmaetalk/exceptions")).singleElement()
                .satisfies(e -> assertThat(e).containsEntry("state", "EXPIRED").containsEntry("coveredFindings", 0));
    }

    @Test
    void 예외를_철회하면_바로_다시_열리고_기록은_남는다() {
        upload("gyeongmaetalk", WEBMVC_OLD, GUAVA);
        Map<String, Object> created = createException("gyeongmaetalk", "CVE-2026-47890", null, SSE_REASON, today().plusDays(30));
        long id = ((Number) ((Map<?, ?>) created.get("exception")).get("id")).longValue();

        ResponseEntity<String> noToken = http.exchange("/api/projects/gyeongmaetalk/exceptions/" + id, HttpMethod.DELETE,
                new HttpEntity<>(null, jsonHeaders(null)), String.class);
        assertThat(noToken.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);

        ResponseEntity<Map<String, Object>> revoked = http.exchange("/api/projects/gyeongmaetalk/exceptions/" + id, HttpMethod.DELETE,
                new HttpEntity<>(null, jsonHeaders("test-token")), new ParameterizedTypeReference<>() {
                });

        assertThat(revoked.getBody()).containsEntry("state", "REVOKED");
        assertThat(getList("/api/projects/gyeongmaetalk/findings?status=OPEN")).hasSize(1);
        assertThat(getList("/api/projects/gyeongmaetalk/exceptions")).hasSize(1);
    }

    @Test
    void 미리_등록한_예외가_있으면_새로_나타난_발견은_열리지_않고_알리지도_않는다() {
        upload("gyeongmaetalk", GUAVA);
        createException("gyeongmaetalk", "CVE-2026-47890", null, SSE_REASON, today().plusDays(30));
        Mockito.clearInvocations(notifier);

        Map<String, Object> r = upload("gyeongmaetalk", WEBMVC_OLD, GUAVA);

        assertThat(r).containsEntry("opened", 0).containsEntry("accepted", 1);
        assertThat(sentAlerts()).isEmpty();
    }

    @Test
    void 다른_모듈을_지정한_예외는_적용되지_않는다() {
        upload("gyeongmaetalk", WEBMVC_OLD, GUAVA);

        Map<String, Object> r = createException("gyeongmaetalk", "CVE-2026-47890", "org.springframework:spring-webflux",
                SSE_REASON, today().plusDays(30));

        assertThat(r).containsEntry("accepted", 0);
        assertThat(getList("/api/projects/gyeongmaetalk/findings?status=OPEN")).hasSize(1);
    }

    @Test
    void 사유가_짧거나_만료일이_지났거나_너무_길면_거부한다() {
        upload("gyeongmaetalk", WEBMVC_OLD);

        assertThat(exceptionStatus("gyeongmaetalk", "짧음", today().plusDays(10))).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(exceptionStatus("gyeongmaetalk", SSE_REASON, today().minusDays(1))).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(exceptionStatus("gyeongmaetalk", SSE_REASON, today().plusDays(181))).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(exceptionStatus("gyeongmaetalk", SSE_REASON, today().plusDays(180))).isEqualTo(HttpStatus.CREATED);
        assertThat(exceptionStatus("no-such-project", SSE_REASON, today().plusDays(10))).isEqualTo(HttpStatus.NOT_FOUND);
    }

    @Test
    void 곧_만료되는_예외만_모아_보여준다() {
        upload("gyeongmaetalk", WEBMVC_OLD, GUAVA);
        createException("gyeongmaetalk", "CVE-2026-47890", null, SSE_REASON, today().plusDays(10));
        createException("gyeongmaetalk", "GHSA-other", null, SSE_REASON, today().plusDays(60));

        assertThat(getList("/api/exceptions/expiring")).singleElement()
                .satisfies(e -> assertThat(e).containsEntry("advisory", "CVE-2026-47890").containsEntry("project", "gyeongmaetalk"));
    }

    private LocalDate today() {
        return LocalDate.ofInstant(clock.instant(), ZoneOffset.UTC);
    }

    private Map<String, Object> createException(String project, String advisory, String module, String reason, LocalDate expiresOn) {
        return post("/api/projects/" + project + "/exceptions", exceptionBody(advisory, module, reason, expiresOn), "test-token");
    }

    private HttpStatus exceptionStatus(String project, String reason, LocalDate expiresOn) {
        return HttpStatus.valueOf(http.exchange("/api/projects/" + project + "/exceptions", HttpMethod.POST,
                new HttpEntity<>(exceptionBody("CVE-2026-47890", null, reason, expiresOn), jsonHeaders("test-token")), String.class)
                .getStatusCode().value());
    }

    private static String exceptionBody(String advisory, String module, String reason, LocalDate expiresOn) {
        return "{\"advisory\":\"" + advisory + "\"," + (module == null ? "" : "\"module\":\"" + module + "\",")
                + "\"reason\":\"" + reason + "\",\"expiresOn\":\"" + expiresOn + "\",\"requestedBy\":\"test\"}";
    }

    @SuppressWarnings("unchecked")
    private List<Notifier.Alert> sentAlerts() {
        ArgumentCaptor<List<Notifier.Alert>> captor = ArgumentCaptor.forClass(List.class);
        Mockito.verify(notifier, Mockito.atLeast(0)).send(captor.capture());
        return captor.getAllValues().stream().flatMap(List::stream).toList();
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
