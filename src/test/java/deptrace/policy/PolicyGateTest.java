package deptrace.policy;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import deptrace.analysis.AnalysisResult;
import deptrace.analysis.AnalysisResult.Advisory;
import deptrace.analysis.AnalysisResult.Finding;
import deptrace.osv.Severity;
import deptrace.policy.PolicyGate.PolicyException;

class PolicyGateTest {

    private static final LocalDate TODAY = LocalDate.of(2026, 10, 19);

    @Test
    void 기준_이상_심각도의_배포_범위_취약점은_위반이다() {
        AnalysisResult r = result(
                finding("com.querydsl:querydsl-jpa:5.0.0", true, advisory("GHSA-6q3q-6v5j-h6vg", "CVE-2024-49203", "HIGH")),
                finding("org.apache.commons:commons-lang3:3.17.0", true, advisory("GHSA-low", "CVE-2025-1", "MODERATE")),
                finding("org.assertj:assertj-core:3.25.3", false, advisory("GHSA-test", "CVE-2026-2", "CRITICAL")));

        PolicyGate.Result gate = PolicyGate.evaluate(r, Severity.HIGH, List.of(), TODAY);

        assertThat(gate.passed()).isFalse();
        assertThat(gate.violations()).extracting(PolicyGate.Violation::coordinate).containsExactly("com.querydsl:querydsl-jpa:5.0.0");
    }

    @Test
    void CVE_별칭과_패키지가_맞는_유효한_예외는_인정한다() {
        AnalysisResult r = result(finding("com.querydsl:querydsl-jpa:5.0.0", true,
                advisory("GHSA-6q3q-6v5j-h6vg", "CVE-2024-49203", "HIGH")));
        PolicyException ok = new PolicyException("CVE-2024-49203", "com.querydsl:querydsl-jpa", "orderBy 고정 필드만 사용", "2027-01-19");

        PolicyGate.Result gate = PolicyGate.evaluate(r, Severity.HIGH, List.of(ok), TODAY);

        assertThat(gate.passed()).isTrue();
        assertThat(gate.accepted()).hasSize(1);
    }

    @Test
    void 패키지가_다르면_같은_ID라도_인정하지_않는다() {
        AnalysisResult r = result(finding("org.springframework:spring-webmvc:6.2.19", true,
                advisory("GHSA-pc63-qcmh-9cmg", "CVE-2026-47884", "CRITICAL")));
        PolicyException other = new PolicyException("CVE-2026-47884", "org.springframework:spring-webflux", "사유", "2027-01-19");

        assertThat(PolicyGate.evaluate(r, Severity.HIGH, List.of(other), TODAY).passed()).isFalse();
    }

    @Test
    void 만료된_예외는_다시_위반이_된다() {
        AnalysisResult r = result(finding("g:a:1", true, advisory("GHSA-a", "CVE-2026-3", "HIGH")));
        PolicyException expired = new PolicyException("CVE-2026-3", null, "한시 예외", "2026-10-18");

        PolicyGate.Result gate = PolicyGate.evaluate(r, Severity.HIGH, List.of(expired), TODAY);

        assertThat(gate.passed()).isFalse();
        assertThat(gate.violations().get(0).note()).contains("만료");
    }

    @Test
    void 사유나_만료일이_없는_예외는_설정_오류다() {
        AnalysisResult r = result();
        PolicyException noReason = new PolicyException("CVE-2026-3", null, " ", "2027-01-01");
        PolicyException badDate = new PolicyException("CVE-2026-4", null, "사유", "내년");

        PolicyGate.Result gate = PolicyGate.evaluate(r, Severity.HIGH, List.of(noReason, badDate), TODAY);

        assertThat(gate.passed()).isFalse();
        assertThat(gate.problems()).hasSize(2);
    }

    @Test
    void YAML_예외_파일을_읽는다(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("exceptions.yml");
        Files.writeString(file, """
                exceptions:
                  - id: CVE-2024-49203
                    package: com.querydsl:querydsl-jpa
                    reason: >-
                      orderBy 고정 필드만 사용
                    expires: 2027-01-19
                """);

        List<PolicyException> list = PolicyGate.loadExceptions(file);

        assertThat(list).containsExactly(new PolicyException("CVE-2024-49203", "com.querydsl:querydsl-jpa", "orderBy 고정 필드만 사용", "2027-01-19"));
    }

    static AnalysisResult result(Finding... findings) {
        return new AnalysisResult("2026-10-19T00:00:00+09:00", ":", "productionRuntimeClasspath",
                List.of("productionRuntimeClasspath"), List.of(), List.of(findings),
                new AnalysisResult.Summary(0, findings.length, findings.length, 0, 0, Map.of(), Map.of()));
    }

    static Finding finding(String coordinate, boolean inPrimary, Advisory... advisories) {
        int i = coordinate.lastIndexOf(':');
        return new Finding(coordinate, coordinate.substring(0, i), coordinate.substring(i + 1), inPrimary,
                List.of(inPrimary ? "productionRuntimeClasspath" : "testRuntimeClasspath"), advisories[0].severity(),
                List.of(advisories), "TRANSITIVE", "", false, 0, List.of(), null, null, false, false, List.of(),
                "NO_FIX", "조치");
    }

    static Advisory advisory(String id, String cve, String severity) {
        return new Advisory(id, cve, List.of(cve), severity, "summary", null, null, List.of());
    }
}
