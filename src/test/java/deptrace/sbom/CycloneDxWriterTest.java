package deptrace.sbom;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.util.List;
import java.util.Map;

import org.cyclonedx.Version;
import org.cyclonedx.exception.ParseException;
import org.cyclonedx.parsers.JsonParser;
import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import deptrace.GraphFixture;
import deptrace.analysis.AnalysisResult;
import deptrace.analysis.AnalysisResult.Advisory;
import deptrace.analysis.AnalysisResult.Finding;
import deptrace.graph.ResolvedGraph;
import deptrace.license.LicenseResolver;
import deptrace.license.LicenseResolver.ComponentLicense;
import deptrace.license.Pom.DeclaredLicense;
import deptrace.model.Coordinate;
import deptrace.policy.PolicyGate.PolicyException;

class CycloneDxWriterTest {

    private static final LocalDate TODAY = LocalDate.of(2026, 11, 18);
    private static final String WEBMVC = "org.springframework:spring-webmvc:6.2.19";
    private static final String CORE = "org.springframework:spring-core:6.2.19";
    private static final String LOGBACK = "ch.qos.logback:logback-classic:1.5.34";
    private static final String MYSQL = "com.mysql:mysql-connector-j:9.7.0";
    private static final String BOM = "org.springframework.boot:spring-boot-dependencies:3.5.16";

    /** 루트 → webmvc → core, 루트 → logback, 루트 → mysql, 그리고 BOM 제약 엣지. */
    private static ResolvedGraph graph() {
        return GraphFixture.graph()
                .node(WEBMVC, "REQUESTED").node(CORE, "REQUESTED", "SELECTED_BY_RULE").node(LOGBACK, "REQUESTED")
                .node(MYSQL, "REQUESTED").node(BOM, "REQUESTED")
                .edge(GraphFixture.ROOT, "org.springframework:spring-webmvc:", WEBMVC)
                .edge(WEBMVC, "org.springframework:spring-core:6.2.19", CORE)
                .edge(GraphFixture.ROOT, "ch.qos.logback:logback-classic:", LOGBACK)
                .edge(GraphFixture.ROOT, "com.mysql:mysql-connector-j:", MYSQL)
                .constraintEdge(BOM, "org.springframework:spring-core:6.2.19", CORE)
                .build();
    }

    private static ComponentLicense license(String coordinate, String... names) {
        List<DeclaredLicense> declared = java.util.Arrays.stream(names).map(n -> new DeclaredLicense(n, null)).toList();
        return LicenseResolver.result(Coordinate.parse(coordinate).orElseThrow(), LicenseResolver.Status.DECLARED, null, declared);
    }

    private static Finding finding(String coordinate, Advisory... advisories) {
        int i = coordinate.lastIndexOf(':');
        return new Finding(coordinate, coordinate.substring(0, i), coordinate.substring(i + 1), true,
                List.of("productionRuntimeClasspath"), advisories[0].severity(), List.of(advisories), "BOM_MANAGED", "", false, 1,
                List.of(), "7.0.9", null, true, true, List.of(), "UPGRADE_PLATFORM", "Spring Boot 업그레이드");
    }

    private static AnalysisResult analysis(Finding... findings) {
        return new AnalysisResult("2026-11-18T00:00:00Z", ":", "productionRuntimeClasspath", List.of("productionRuntimeClasspath"),
                List.of(), List.of(findings), new AnalysisResult.Summary(0, 0, 0, 0, 0, Map.of(), Map.of()));
    }

    private static ObjectNode sample() {
        Advisory sse = new Advisory("GHSA-j9f9-w8pj-32f8", "CVE-2026-47890", List.of("CVE-2026-47890"), "CRITICAL", "SSE", null, "7.0.9", List.of());
        Advisory other = new Advisory("GHSA-new", "CVE-2026-1", List.of("CVE-2026-1"), "MODERATE", "other", null, "7.0.9", List.of());
        return CycloneDxWriter.write(graph(),
                List.of(license(WEBMVC, "Apache License, Version 2.0"), license(CORE, "Apache-2.0"),
                        license(LOGBACK, "EPL-2.0", "LGPL-2.1-only"),
                        license(MYSQL, "The GNU General Public License, v2 with Universal FOSS Exception, v1.0"),
                        license(BOM, "Custom License")),
                analysis(finding(WEBMVC, sse, other)),
                List.of(new PolicyException("GHSA-j9f9-w8pj-32f8", "org.springframework:spring-webmvc", "SseEmitter 사용 없음", "2027-01-19")),
                TODAY, "0.1.0");
    }

    @Test
    void CycloneDX_1_6_공식_스키마를_통과한다() throws Exception {
        List<ParseException> errors = new JsonParser().validate(CycloneDxWriter.toJson(sample()), Version.VERSION_16);

        assertThat(errors).isEmpty();
    }

    @Test
    void 라이선스는_단일_식별자_복합_식_미식별_원문으로_구분해_쓴다() {
        JsonNode components = sample().get("components");

        assertThat(component(components, CORE).at("/licenses/0/license/id").asText()).isEqualTo("Apache-2.0");
        assertThat(component(components, LOGBACK).at("/licenses/0/expression").asText()).isEqualTo("EPL-2.0 OR LGPL-2.1-only");
        // WITH 예외 조항은 license.id가 아니라 expression이어야 스키마를 통과한다
        assertThat(component(components, MYSQL).at("/licenses/0/expression").asText())
                .isEqualTo("GPL-2.0-only WITH Universal-FOSS-exception-1.0");
        // 모르는 것은 SPDX로 추측하지 않고 원문 그대로
        assertThat(component(components, BOM).at("/licenses/0/license/name").asText()).isEqualTo("Custom License");
    }

    @Test
    void 의존_관계에는_제약_엣지를_넣지_않는다() {
        JsonNode deps = sample().get("dependencies");
        String bomRef = Coordinate.parse(BOM).orElseThrow().purl();

        JsonNode bom = find(deps, "ref", bomRef);
        assertThat(bom.get("dependsOn")).isEmpty();
        JsonNode webmvc = find(deps, "ref", Coordinate.parse(WEBMVC).orElseThrow().purl());
        assertThat(webmvc.get("dependsOn").get(0).asText()).isEqualTo(Coordinate.parse(CORE).orElseThrow().purl());
        // 루트는 직접 의존성 3개
        assertThat(find(deps, "ref", "pkg:maven/com.example/app@1.0.0").get("dependsOn")).hasSize(3);
    }

    @Test
    void 유효한_예외는_not_affected_나머지는_in_triage로_쓴다() {
        JsonNode vulns = sample().get("vulnerabilities");

        JsonNode sse = find(vulns, "id", "GHSA-j9f9-w8pj-32f8");
        assertThat(sse.at("/analysis/state").asText()).isEqualTo("not_affected");
        assertThat(sse.at("/analysis/justification").asText()).isEqualTo("code_not_reachable");
        assertThat(sse.at("/analysis/detail").asText()).contains("SseEmitter 사용 없음");
        assertThat(sse.at("/ratings/0/severity").asText()).isEqualTo("critical");
        assertThat(sse.at("/references/0/id").asText()).isEqualTo("CVE-2026-47890");

        JsonNode other = find(vulns, "id", "GHSA-new");
        assertThat(other.at("/analysis/state").asText()).isEqualTo("in_triage");
        assertThat(other.at("/ratings/0/severity").asText()).isEqualTo("medium");
    }

    @Test
    void 만료된_예외는_not_affected로_쓰지_않는다() {
        Advisory sse = new Advisory("GHSA-j9f9-w8pj-32f8", "CVE-2026-47890", List.of("CVE-2026-47890"), "CRITICAL", "SSE", null, "7.0.9", List.of());
        ObjectNode bom = CycloneDxWriter.write(graph(), List.of(), analysis(finding(WEBMVC, sse)),
                List.of(new PolicyException("GHSA-j9f9-w8pj-32f8", null, "SseEmitter 사용 없음", "2026-11-17")), TODAY, "0.1.0");

        assertThat(bom.at("/vulnerabilities/0/analysis/state").asText()).isEqualTo("in_triage");
    }

    /** DEPTRACE_SBOM에 실제 프로젝트에서 만든 SBOM 경로를 주면 그 파일도 스키마로 검증한다 (없으면 건너뜀). */
    @Test
    void 실제_SBOM_파일도_스키마를_통과한다() throws Exception {
        String path = System.getenv("DEPTRACE_SBOM");
        assumeTrue(path != null && Files.exists(Path.of(path)));

        assertThat(new JsonParser().validate(Path.of(path).toFile(), Version.VERSION_16)).isEmpty();
    }

    private static JsonNode component(JsonNode components, String coordinate) {
        return find(components, "bom-ref", Coordinate.parse(coordinate).orElseThrow().purl());
    }

    private static JsonNode find(JsonNode array, String field, String value) {
        for (JsonNode n : array) {
            if (value.equals(n.path(field).asText())) {
                return n;
            }
        }
        throw new AssertionError(field + "=" + value + " 없음");
    }
}
