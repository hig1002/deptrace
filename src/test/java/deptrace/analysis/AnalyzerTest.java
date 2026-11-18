package deptrace.analysis;

import static deptrace.GraphFixture.ROOT;
import static deptrace.GraphFixture.graph;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.Test;

import deptrace.analysis.AnalysisResult.Finding;
import deptrace.graph.ResolvedGraph;
import deptrace.model.Coordinate;
import deptrace.osv.OsvVulnerability;
import deptrace.osv.Severity;
import deptrace.osv.VulnerabilitySource;
import deptrace.repository.PublishedVersions;

class AnalyzerTest {

    private static final String TOMCAT = "org.apache.tomcat.embed:tomcat-embed-core:10.1.55";
    private static final String NIMBUS = "com.nimbusds:nimbus-jose-jwt:9.37";
    private static final String SECURITY = "org.springframework.security:spring-security-oauth2-jose:6.3.4";
    private static final String ASSERTJ = "org.assertj:assertj-core:3.25.3";

    @Test
    void 수정_지점과_실제_배포_버전을_함께_판단한다() {
        ResolvedGraph prod = graph()
                .node("org.springframework.boot:spring-boot-starter-web:3.5.16", "REQUESTED", "SELECTED_BY_RULE")
                .node(TOMCAT, "REQUESTED", "SELECTED_BY_RULE")
                .node(SECURITY, "REQUESTED", "SELECTED_BY_RULE")
                .node(NIMBUS, "REQUESTED", "SELECTED_BY_RULE")
                .managed("org.apache.tomcat.embed:tomcat-embed-core", "10.1.55")
                .declared("com.nimbusds:nimbus-jose-jwt", "9.37")
                .edge(ROOT, "org.springframework.boot:spring-boot-starter-web", "org.springframework.boot:spring-boot-starter-web:3.5.16")
                .edge("org.springframework.boot:spring-boot-starter-web:3.5.16", "org.apache.tomcat.embed:tomcat-embed-core:10.1.55", TOMCAT)
                .edge(ROOT, "org.springframework.security:spring-security-oauth2-jose", SECURITY)
                .edge(ROOT, "com.nimbusds:nimbus-jose-jwt:9.37", NIMBUS)
                .edge(SECURITY, "com.nimbusds:nimbus-jose-jwt:9.37.3", NIMBUS)
                .build();
        ResolvedGraph test = graph("testRuntimeClasspath")
                .node(ASSERTJ)
                .edge(ROOT, "org.assertj:assertj-core:3.25.3", ASSERTJ)
                .build();

        VulnerabilitySource source = coordinates -> {
            Map<Coordinate, List<OsvVulnerability>> m = new LinkedHashMap<>();
            for (Coordinate c : coordinates) {
                switch (c.module()) {
                    case "org.apache.tomcat.embed:tomcat-embed-core" -> m.put(c, List.of(vuln("GHSA-tomcat", "CVE-2026-1", c.module(), "10.1.58")));
                    case "com.nimbusds:nimbus-jose-jwt" -> m.put(c, List.of(vuln("GHSA-nimbus", "CVE-2023-52428", c.module(), "9.37.2")));
                    case "org.assertj:assertj-core" -> m.put(c, List.of(vuln("GHSA-assertj", "CVE-2026-2", c.module(), "3.27.7")));
                    default -> { }
                }
            }
            return m;
        };
        // Tomcat 10.1.58은 배포되지 않았다 (10.1.57 다음이 10.1.59)
        PublishedVersions published = module -> module.endsWith("tomcat-embed-core")
                ? Optional.of(List.of("10.1.55", "10.1.57", "10.1.59", "10.1.60")) : Optional.empty();

        AnalysisResult result = new Analyzer(source, published).analyze(List.of(prod, test));

        Finding tomcat = find(result, "org.apache.tomcat.embed:tomcat-embed-core");
        assertThat(tomcat.remediation()).isEqualTo("UPGRADE_PLATFORM");
        assertThat(tomcat.fixVersion()).isEqualTo("10.1.58");
        assertThat(tomcat.publishedFixVersion()).isEqualTo("10.1.59");
        assertThat(tomcat.remediationAdvice()).contains("10.1.59").contains("배포되지 않아");

        Finding nimbus = find(result, "com.nimbusds:nimbus-jose-jwt");
        assertThat(nimbus.remediation()).isEqualTo("REMOVE_DIRECT_PIN");  // 선언을 지우면 9.37.3이 선택되어 9.37.2 이상
        assertThat(nimbus.downgraded()).isTrue();

        Finding assertj = find(result, "org.assertj:assertj-core");
        assertThat(assertj.inPrimary()).isFalse();
        assertThat(assertj.remediation()).isEqualTo("TEST_ONLY");

        assertThat(result.summary().vulnerableInPrimary()).isEqualTo(2);
        assertThat(result.findings().get(0).inPrimary()).isTrue();  // 배포 범위가 먼저 나온다
    }

    @Test
    void 같은_CVE가_GHSA와_CVE_두_ID로_와도_한_건으로_센다() {
        ResolvedGraph prod = graph().node("g:a:1").edge(ROOT, "g:a:1", "g:a:1").build();
        VulnerabilitySource source = (Collection<Coordinate> coordinates) -> Map.of(
                new Coordinate("g", "a", "1"),
                List.of(vuln("GHSA-xxxx", "CVE-2026-9", "g:a", "2"), vuln("CVE-2026-9", "GHSA-xxxx", "g:a", "2")));

        AnalysisResult result = new Analyzer(source, PublishedVersions.NONE).analyze(List.of(prod));

        assertThat(result.findings().get(0).advisories()).hasSize(1);
        assertThat(result.summary().uniqueAdvisoriesPrimary()).isEqualTo(1);
    }

    private static Finding find(AnalysisResult r, String module) {
        return r.findings().stream().filter(f -> f.module().equals(module)).findFirst().orElseThrow();
    }

    private static OsvVulnerability vuln(String id, String alias, String module, String fixed) {
        return new OsvVulnerability(id, id + " summary", List.of(alias), "2026-01-01T00:00:00Z", null, Severity.HIGH,
                List.of(new OsvVulnerability.Affected("Maven", module,
                        List.of(new OsvVulnerability.Range("ECOSYSTEM", List.of(
                                new OsvVulnerability.Event("introduced", "0"), new OsvVulnerability.Event("fixed", fixed)))),
                        List.of())));
    }
}
