package deptrace.nvd;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.LocalDate;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.Test;

import deptrace.GraphFixture;
import deptrace.analysis.AnalysisResult;
import deptrace.analysis.AnalysisResult.Advisory;
import deptrace.analysis.AnalysisResult.Finding;
import deptrace.graph.ResolvedGraph;
import deptrace.model.Coordinate;
import deptrace.nvd.GhsaLookup.Review;
import deptrace.nvd.GhsaLookup.Status;
import deptrace.nvd.NvdCve.CpeMatch;
import deptrace.osv.Severity;
import deptrace.policy.PolicyGate.PolicyException;
import deptrace.repository.PublishedVersions;

class GapAnalyzerTest {

    private static final String SF = "vmware:spring_framework";
    private static final String CORE = "org.springframework:spring-core:6.2.19";
    private static final String WEB = "org.springframework:spring-web:6.2.19";
    private static final String WEBMVC = "org.springframework:spring-webmvc:6.2.19";
    private static final String OTEL = "io.opentelemetry:opentelemetry-api:1.49.0";
    private static final String TCNATIVE = "io.netty:netty-tcnative-classes:2.0.70.Final";

    private static ResolvedGraph graph() {
        GraphFixture g = GraphFixture.graph();
        for (String c : List.of(CORE, WEB, WEBMVC, OTEL, TCNATIVE)) {
            g.node(c, "REQUESTED").edge(GraphFixture.ROOT, c.substring(0, c.lastIndexOf(':') + 1), c);
        }
        return g.build();
    }

    private static CpeMatch range(String vp, String start, String endExcl) {
        return CpeMatch.vulnerable("cpe:2.3:a:" + vp + ":*:*:*:*:*:*:*:*", start, endExcl);
    }

    /** NVD 데이터: Spring 미검토 1건, OSV가 이미 보고한 1건, 검토 결과 다른 모듈 1건, Netty 범위 1건. */
    private static final Map<String, List<NvdCve>> NVD = Map.of(
            SF, List.of(
                    NvdCve.simple("CVE-2026-47886", Severity.HIGH, range(SF, "6.2.0", "6.2.20"), range(SF, "7.0.0", "7.0.8.1")),
                    NvdCve.simple("CVE-2026-47890", Severity.CRITICAL, range(SF, "6.2.0", "6.2.20")),
                    NvdCve.simple("CVE-REVIEWED", Severity.HIGH, range(SF, "6.2.0", "6.2.20"))),
            "netty:netty", List.of(NvdCve.simple("CVE-2026-89044", Severity.MODERATE, range("netty:netty", null, "4.1.138"))));

    private static final Map<String, Status> GHSA = Map.of(
            "CVE-2026-47886", new Status(Review.UNREVIEWED, "GHSA-g782-8rcv-55rh", List.of()),
            "CVE-REVIEWED", new Status(Review.REVIEWED, "GHSA-r", List.of("org.springframework:spring-messaging")));

    /** Maven Central: 6.2.20은 상용 지원판에만 있어 배포되지 않았다. */
    private static final PublishedVersions PUBLISHED = module -> Optional.of(
            List.of("6.2.18", "6.2.19", "7.0.0", "7.0.8", "7.0.9", "7.1.0-M1"));

    private static GapAnalyzer analyzer() {
        ProductMap map = new ProductMap(List.of(
                new ProductMap.Product("Spring Framework", List.of(SF), "org.springframework", "spring-(core|web|webmvc)"),
                new ProductMap.Product("Netty", List.of("netty:netty"), "io.netty", "netty-(?!tcnative|incubator).+")));
        return new GapAnalyzer(map, cpe -> NVD.getOrDefault(cpe, List.of()),
                cve -> GHSA.getOrDefault(cve, new Status(Review.NONE, null, List.of())), PUBLISHED);
    }

    private static AnalysisResult osvReported(String coordinate, String ghsa, String cve) {
        int i = coordinate.lastIndexOf(':');
        Finding f = new Finding(coordinate, coordinate.substring(0, i), coordinate.substring(i + 1), true,
                List.of("productionRuntimeClasspath"), "CRITICAL",
                List.of(new Advisory(ghsa, cve, List.of(cve), "CRITICAL", "", null, null, List.of())),
                "BOM_MANAGED", "", false, 1, List.of(), null, null, false, false, List.of(), "NO_FIX", "");
        return new AnalysisResult("", ":", "productionRuntimeClasspath", List.of(), List.of(), List.of(f),
                new AnalysisResult.Summary(0, 0, 0, 0, 0, Map.of(), Map.of()));
    }

    @Test
    void 제품_단위로_한_번만_보고하고_OSV_보고분과_검토된_권고는_뺀다() {
        GapAnalyzer.Result r = analyzer().analyze(graph(), osvReported(WEBMVC, "GHSA-j9f9-w8pj-32f8", "CVE-2026-47890"));

        assertThat(r.gaps()).extracting(GapAnalyzer.Gap::cve).containsExactly("CVE-2026-47886");
        GapAnalyzer.Gap gap = r.gaps().get(0);
        // spring-core, spring-web, spring-webmvc 세 jar에 걸리지만 한 건이다
        assertThat(gap.modules()).hasSize(3);
        assertThat(gap.ghsaReview()).isEqualTo("UNREVIEWED");
        assertThat(r.coveredByOsv()).containsExactly("CVE-2026-47890");
        assertThat(r.reviewedElsewhere()).singleElement().asString().contains("spring-messaging");
    }

    @Test
    void 다음_안전_버전은_다른_범위와_미배포_버전을_건너뛴다() {
        GapAnalyzer.Gap gap = analyzer().analyze(graph(), null).gaps().stream()
                .filter(g -> g.cve().equals("CVE-2026-47886")).findFirst().orElseThrow();

        // 6.2.20은 배포되지 않았고, 7.0.0~7.0.8은 같은 CVE의 다른 범위에 든다
        assertThat(gap.nextSafe()).isEqualTo("7.0.9");
    }

    @Test
    void 대응표에_없는_모듈과_버전_체계가_다른_하위_모듈은_보지_않는다() {
        GapAnalyzer.Result r = analyzer().analyze(graph(), null);

        // netty-tcnative 2.0.70은 Netty 4.1.138 미만이지만 Netty 본체가 아니다
        assertThat(r.gaps()).extracting(GapAnalyzer.Gap::product).doesNotContain("Netty");
        assertThat(r.productsChecked()).doesNotContainKey("OpenTelemetry");
    }

    @Test
    void 게이트는_기준_심각도와_예외를_적용한다() {
        GapAnalyzer.Result r = analyzer().analyze(graph(), null);
        LocalDate today = LocalDate.of(2026, 11, 18);

        assertThat(GapAnalyzer.gate(r, Severity.HIGH, List.of(), today).passed()).isFalse();
        GapAnalyzer.GateResult excepted = GapAnalyzer.gate(r, Severity.HIGH, List.of(
                new PolicyException("CVE-2026-47886", "org.springframework:spring-core", "SpEL에 사용자 입력 없음", "2027-01-19"),
                new PolicyException("CVE-2026-47890", null, "SSE 미사용", "2027-01-19"),
                new PolicyException("CVE-REVIEWED", null, "-", "2027-01-19")), today);
        assertThat(excepted.passed()).isTrue();
        assertThat(excepted.accepted()).anySatisfy(a -> assertThat(a).contains("SpEL"));
    }

    @Test
    void 기본_대응표는_log4j_api와_tcnative를_연결하지_않는다() {
        ProductMap map = ProductMap.defaults();

        assertThat(map.productOf(Coordinate.parse("org.apache.logging.log4j:log4j-api:2.24.3").orElseThrow())).isEmpty();
        assertThat(map.productOf(Coordinate.parse("org.apache.logging.log4j:log4j-core:2.24.3").orElseThrow())).isPresent();
        assertThat(map.productOf(Coordinate.parse(TCNATIVE).orElseThrow())).isEmpty();
        assertThat(map.productOf(Coordinate.parse("io.netty:netty-codec-http:4.1.137.Final").orElseThrow()))
                .get().extracting(ProductMap.Product::name).isEqualTo("Netty");
        assertThat(map.productOf(Coordinate.parse(OTEL).orElseThrow())).isEmpty();
    }
}
