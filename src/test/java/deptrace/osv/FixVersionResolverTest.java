package deptrace.osv;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

import deptrace.model.Coordinate;
import deptrace.osv.OsvVulnerability.Affected;
import deptrace.osv.OsvVulnerability.Event;
import deptrace.osv.OsvVulnerability.Range;

class FixVersionResolverTest {

    private static final Coordinate SPRING_WEBMVC_6_1_14 = new Coordinate("org.springframework", "spring-webmvc", "6.1.14");

    @Test
    void 현재_버전이_속한_범위를_닫는_fixed가_같은_라인_수정_버전이다() {
        OsvVulnerability v = vuln(affected("org.springframework:spring-webmvc",
                range(ev("introduced", "6.1.0"), ev("fixed", "6.1.15")),
                range(ev("introduced", "6.2.0"), ev("fixed", "6.2.2"))));

        FixVersionResolver.FixInfo fix = FixVersionResolver.resolve(v, SPRING_WEBMVC_6_1_14);

        assertThat(fix.sameLine()).isEqualTo("6.1.15");
        assertThat(fix.nextSafe()).isEqualTo("6.1.15");
        assertThat(fix.requiresLineChange()).isFalse();
    }

    @Test
    void 현재_라인이_last_affected로_끝나면_다음_라인의_fixed를_안전한_버전으로_고른다() {
        // Spring 6.1.x처럼 공개 수정 버전 없이 last_affected로 끝나는 경우 (상용 지원만 존재)
        OsvVulnerability v = vuln(
                affected("org.springframework:spring-webmvc", range(ev("introduced", "6.1.0"), ev("last_affected", "6.1.21"))),
                affected("org.springframework:spring-webmvc", range(ev("introduced", "6.2.0"), ev("fixed", "6.2.19"))),
                affected("org.springframework:spring-webmvc", range(ev("introduced", "7.0.0"), ev("fixed", "7.0.8"))));

        FixVersionResolver.FixInfo fix = FixVersionResolver.resolve(v, SPRING_WEBMVC_6_1_14);

        assertThat(fix.sameLine()).isNull();
        assertThat(fix.nextSafe()).isEqualTo("6.2.19");
        assertThat(fix.requiresLineChange()).isTrue();
    }

    @Test
    void 다른_범위에_다시_걸리는_fixed는_안전한_버전이_아니다() {
        // 6.2.0에서 고쳐졌지만 6.2.0~6.2.5에서 다시 취약해진 경우 → 6.2.0은 건너뛰고 6.2.5
        OsvVulnerability v = vuln(affected("g:a",
                range(ev("introduced", "0"), ev("fixed", "6.2.0")),
                range(ev("introduced", "6.2.0"), ev("fixed", "6.2.5"))));

        FixVersionResolver.FixInfo fix = FixVersionResolver.resolve(v, new Coordinate("g", "a", "6.1.0"));

        assertThat(fix.nextSafe()).isEqualTo("6.2.5");
    }

    @Test
    void 이벤트_순서가_섞여_있어도_Maven_버전_순으로_해석한다() {
        OsvVulnerability v = vuln(affected("g:a", range(ev("fixed", "2.5.2"), ev("introduced", "0"))));

        assertThat(FixVersionResolver.resolve(v, new Coordinate("g", "a", "2.5.1")).sameLine()).isEqualTo("2.5.2");
        assertThat(FixVersionResolver.resolve(v, new Coordinate("g", "a", "2.5.2")).sameLine()).isNull();
    }

    @Test
    void 같은_권고가_다른_좌표에만_수정_버전을_두면_좌표_이동_단서로_반환한다() {
        // ion-java: software.amazon.ion 좌표는 수정 버전 없음, com.amazon.ion 좌표는 1.10.5에서 수정
        OsvVulnerability v = vuln(
                affected("com.amazon.ion:ion-java", range(ev("introduced", "0"), ev("fixed", "1.10.5"))),
                affected("software.amazon.ion:ion-java", range(ev("introduced", "0"))));

        FixVersionResolver.FixInfo fix = FixVersionResolver.resolve(v, new Coordinate("software.amazon.ion", "ion-java", "1.0.2"));

        assertThat(fix.nextSafe()).isNull();
        assertThat(fix.alternatives()).containsExactly("com.amazon.ion:ion-java:1.10.5");
    }

    @Test
    void Maven_한정자_규칙으로_비교한다() {
        // 4.1.114.Final < 4.1.137.Final, 1.0-rc1 < 1.0
        OsvVulnerability netty = vuln(affected("io.netty:netty-handler", range(ev("introduced", "0"), ev("fixed", "4.1.137.Final"))));
        OsvVulnerability rc = vuln(affected("g:a", range(ev("introduced", "0"), ev("fixed", "1.0"))));

        assertThat(FixVersionResolver.resolve(netty, new Coordinate("io.netty", "netty-handler", "4.1.114.Final")).nextSafe())
                .isEqualTo("4.1.137.Final");
        assertThat(FixVersionResolver.resolve(rc, new Coordinate("g", "a", "1.0-rc1")).nextSafe()).isEqualTo("1.0");
    }

    private static OsvVulnerability vuln(Affected... affected) {
        return new OsvVulnerability("GHSA-test", "test", List.of("CVE-0000-0001"), "2026-01-01T00:00:00Z", null,
                Severity.HIGH, List.of(affected));
    }

    private static Affected affected(String name, Range... ranges) {
        return new Affected("Maven", name, List.of(ranges), List.of());
    }

    private static Range range(Event... events) {
        return new Range("ECOSYSTEM", new ArrayList<>(List.of(events)));
    }

    private static Event ev(String type, String version) {
        return new Event(type, version);
    }
}
