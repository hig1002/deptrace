package deptrace.report;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import deptrace.analysis.AnalysisResult;
import deptrace.analysis.AnalysisResult.Advisory;
import deptrace.analysis.AnalysisResult.Finding;

class ResultDiffTest {

    @Test
    void 구성요소_상향_하향_추가_제거와_취약점_해결_신규를_구분한다() {
        AnalysisResult before = result(
                List.of("com.nimbusds:nimbus-jose-jwt:9.37", "com.squareup.okhttp3:logging-interceptor:4.12.0", "software.amazon.ion:ion-java:1.0.2"),
                finding("com.nimbusds:nimbus-jose-jwt:9.37", "CVE-2023-52428"),
                finding("software.amazon.ion:ion-java:1.0.2", "CVE-2024-21634"));
        AnalysisResult after = result(
                List.of("com.nimbusds:nimbus-jose-jwt:10.9.1", "com.squareup.okhttp3:logging-interceptor:4.10.0", "io.opentelemetry:opentelemetry-api:1.49.0"),
                finding("io.opentelemetry:opentelemetry-api:1.49.0", "CVE-2026-45292"));

        ResultDiff.Diff d = ResultDiff.compare(before, after);

        assertThat(d.upgraded()).extracting(ResultDiff.ComponentChange::module).containsExactly("com.nimbusds:nimbus-jose-jwt");
        assertThat(d.downgraded()).extracting(ResultDiff.ComponentChange::module).containsExactly("com.squareup.okhttp3:logging-interceptor");
        assertThat(d.added()).containsExactly("io.opentelemetry:opentelemetry-api:1.49.0");
        assertThat(d.removed()).containsExactly("software.amazon.ion:ion-java:1.0.2");
        assertThat(d.fixedAdvisories()).containsExactly("com.nimbusds:nimbus-jose-jwt CVE-2023-52428", "software.amazon.ion:ion-java CVE-2024-21634");
        assertThat(d.newAdvisories()).containsExactly("io.opentelemetry:opentelemetry-api CVE-2026-45292");
        assertThat(ResultDiff.render(d)).contains("↓ com.squareup.okhttp3:logging-interceptor 4.12.0 → 4.10.0");
    }

    private static AnalysisResult result(List<String> components, Finding... findings) {
        return new AnalysisResult("t", ":", "productionRuntimeClasspath", List.of("productionRuntimeClasspath"),
                components, List.of(findings),
                new AnalysisResult.Summary(components.size(), findings.length, findings.length, findings.length, findings.length,
                        Map.of("HIGH", findings.length), Map.of()));
    }

    private static Finding finding(String coordinate, String cve) {
        int i = coordinate.lastIndexOf(':');
        Advisory a = new Advisory("GHSA-" + cve, cve, List.of(cve), "HIGH", "", null, null, List.of());
        return new Finding(coordinate, coordinate.substring(0, i), coordinate.substring(i + 1), true,
                List.of("productionRuntimeClasspath"), "HIGH", List.of(a), "TRANSITIVE", "", false, 0, List.of(),
                null, null, false, false, List.of(), "NO_FIX", "");
    }
}
