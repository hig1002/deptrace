package deptrace.nvd;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import deptrace.nvd.NvdCve.Config;
import deptrace.nvd.NvdCve.CpeMatch;
import deptrace.nvd.NvdCve.Node;
import deptrace.osv.Severity;

/** 테스트 값은 경매톡 점검에서 실제로 본 NVD 설정을 옮겼다. */
class CpeMatcherTest {

    private static final String SF = "vmware:spring_framework";
    private static final Map<String, Set<String>> NONE = Map.of();

    private static CpeMatch any(String vendorProduct, String start, String endExcl) {
        return CpeMatch.vulnerable("cpe:2.3:a:" + vendorProduct + ":*:*:*:*:*:*:*:*", start, endExcl);
    }

    @Test
    void 라인별_범위로_판정한다() {
        // CVE-2026-47886: 6.2.0 이상 6.2.20 미만, 7.0.0 이상 7.0.8.1 미만
        NvdCve cve = NvdCve.simple("CVE-2026-47886", Severity.HIGH, any(SF, "6.2.0", "6.2.20"), any(SF, "7.0.0", "7.0.8.1"));

        assertThat(CpeMatcher.match(cve, SF, "6.2.19", NONE)).isPresent();
        assertThat(CpeMatcher.match(cve, SF, "6.2.20", NONE)).isEmpty();
        assertThat(CpeMatcher.match(cve, SF, "7.0.8", NONE)).isPresent();
        assertThat(CpeMatcher.match(cve, SF, "7.0.9", NONE)).isEmpty();
        assertThat(CpeMatcher.match(cve, SF, "6.1.30", NONE)).isEmpty();
    }

    @Test
    void Java가_아닌_target_sw는_받지_않는다() {
        // CVE-2026-24051: OpenTelemetry Go SDK. Dependency-Check는 이것을 Java용 opentelemetry jar에 붙였다
        NvdCve go = NvdCve.simple("CVE-2026-24051", Severity.HIGH, new CpeMatch(
                "cpe:2.3:a:opentelemetry:opentelemetry:*:*:*:*:*:go:*:*", true, "1.21.0", null, null, "1.40.0"));

        assertThat(CpeMatcher.match(go, "opentelemetry:opentelemetry", "1.37.0", NONE)).isEmpty();
    }

    @Test
    void 버전_하이픈은_모든_버전이_아니라_해당_없음이다() {
        // CVE-2016-5425: RHEL Tomcat 패키지의 권한 문제. cpe 버전 "-"
        NvdCve rhel = NvdCve.simple("CVE-2016-5425", Severity.HIGH,
                new CpeMatch("cpe:2.3:a:apache:tomcat:-:*:*:*:*:*:*:*", true, null, null, null, null));

        assertThat(CpeMatcher.match(rhel, "apache:tomcat", "10.1.59", NONE)).isEmpty();
    }

    @Test
    void AND_조건의_다른_제품은_클래스패스_버전으로_확인한다() {
        // CVE-2018-1258: Spring Security(모든 버전) AND Spring Framework 5.0.5
        NvdCve cve = new NvdCve("CVE-2018-1258", "", "Analyzed", Severity.HIGH, "", List.of(new Config(null, List.of(
                new Node("AND", false, List.of(
                        new CpeMatch("cpe:2.3:a:pivotal_software:spring_security:*:*:*:*:*:*:*:*", true, null, null, null, null),
                        new CpeMatch("cpe:2.3:a:vmware:spring_framework:5.0.5:*:*:*:*:*:*:*", true, null, null, null, null)))))));

        assertThat(CpeMatcher.match(cve, "pivotal_software:spring_security", "6.5.11", Map.of(SF, Set.of("6.2.19")))).isEmpty();
        assertThat(CpeMatcher.match(cve, "pivotal_software:spring_security", "5.0.4", Map.of(SF, Set.of("5.0.5")))).isPresent();
    }

    @Test
    void 클래스패스로_확인할_수_없는_플랫폼_조건은_만족하지_않는_것으로_본다() {
        // "제품 AND (Oracle Linux에서 실행)" 형태. OS는 알 수 없으므로 보고하지 않는다
        NvdCve cve = new NvdCve("CVE-X", "", "Analyzed", Severity.HIGH, "", List.of(new Config("AND", List.of(
                new Node("OR", false, List.of(any("apache:tomcat", "10.1.0", "10.1.60"))),
                new Node("OR", false, List.of(new CpeMatch("cpe:2.3:o:oracle:linux:7:*:*:*:*:*:*:*", false, null, null, null, null)))))));

        assertThat(CpeMatcher.match(cve, "apache:tomcat", "10.1.59", NONE)).isEmpty();
    }

    @Test
    void 변형_꼬리표를_떼고_비교한다() {
        // NVD는 "33.7.2"로 적지만 Maven에서는 33.7.2-jre가 33.7.2보다 크게 정렬된다
        NvdCve guava = NvdCve.simple("CVE-G", Severity.HIGH, any("google:guava", null, "33.7.2"));

        assertThat(CpeMatcher.match(guava, "google:guava", "33.6.0-jre", NONE)).isPresent();
        assertThat(CpeMatcher.match(guava, "google:guava", "33.7.2-jre", NONE)).isEmpty();
    }

    @Test
    void Final_한정자와_이스케이프된_제품명을_처리한다() {
        NvdCve netty = NvdCve.simple("CVE-2026-89044", Severity.MODERATE, any("netty:netty", "4.1.133", "4.1.138"));
        NvdCve mysql = NvdCve.simple("CVE-2026-60586", Severity.HIGH,
                new CpeMatch("cpe:2.3:a:oracle:mysql_connector\\/j:9.7.0:*:*:*:*:*:*:*", true, null, null, null, null));

        assertThat(CpeMatcher.match(netty, "netty:netty", "4.1.137.Final", NONE)).isPresent();
        assertThat(CpeMatcher.match(netty, "netty:netty", "4.1.138.Final", NONE)).isEmpty();
        assertThat(CpeMatcher.match(mysql, "oracle:mysql_connector\\/j", "9.7.0", NONE)).isPresent();
        assertThat(CpeMatcher.match(mysql, "oracle:mysql_connector\\/j", "26.7.0", NONE)).isEmpty();
    }
}
