package deptrace.license;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import deptrace.license.LicensePolicy.LicenseException;
import deptrace.license.LicensePolicy.Verdict;
import deptrace.license.LicenseResolver.ComponentLicense;
import deptrace.license.LicenseResolver.Status;
import deptrace.license.Pom.DeclaredLicense;
import deptrace.model.Coordinate;

class LicensePolicyTest {

    private static final LocalDate TODAY = LocalDate.of(2026, 11, 18);
    private static final String MYSQL = "The GNU General Public License, v2 with Universal FOSS Exception, v1.0";

    private static ComponentLicense license(String coordinate, String... names) {
        List<DeclaredLicense> declared = java.util.Arrays.stream(names).map(n -> new DeclaredLicense(n, null)).toList();
        return LicenseResolver.result(Coordinate.parse(coordinate).orElseThrow(), Status.DECLARED, null, declared);
    }

    private static Verdict verdict(LicensePolicy policy, ComponentLicense l) {
        return policy.evaluate(List.of(l), TODAY).decisions().get(0).verdict();
    }

    @Test
    void 기본_정책은_강한_카피레프트를_막고_약한_카피레프트는_검토로_둔다() {
        LicensePolicy p = LicensePolicy.DEFAULT;

        assertThat(verdict(p, license("com.mysql:mysql-connector-j:9.7.0", MYSQL))).isEqualTo(Verdict.DENIED);
        assertThat(verdict(p, license("org.hibernate.orm:hibernate-core:6.6.53.Final", "GNU Library General Public License v2.1 or later")))
                .isEqualTo(Verdict.REVIEW);
        assertThat(verdict(p, license("com.zaxxer:HikariCP:6.3.3", "The Apache Software License, Version 2.0")))
                .isEqualTo(Verdict.ALLOWED);
        assertThat(verdict(p, license("g:custom:1", "Custom License"))).isEqualTo(Verdict.REVIEW);
    }

    @Test
    void 다중_라이선스는_금지되지_않은_선택지가_있으면_위반이_아니다() {
        LicensePolicy.Result r = LicensePolicy.DEFAULT.evaluate(List.of(license("g:dual:1", "GPL-3.0", "MIT")), TODAY);

        assertThat(r.decisions().get(0).verdict()).isEqualTo(Verdict.ALLOWED);
        assertThat(r.decisions().get(0).chosen()).isEqualTo("MIT");
        assertThat(r.decisions().get(0).note()).contains("선택 가정");
    }

    @Test
    void 식별자_단위_허용과_금지가_분류보다_우선한다() {
        LicensePolicy allowMysql = new LicensePolicy(LicensePolicy.DEFAULT.deny(), LicensePolicy.DEFAULT.review(),
                List.of("GPL-2.0-only WITH Universal-FOSS-exception-1.0"), List.of(), List.of());
        LicensePolicy denyEpl = new LicensePolicy(LicensePolicy.DEFAULT.deny(), LicensePolicy.DEFAULT.review(),
                List.of(), List.of("EPL-2.0"), List.of());

        assertThat(verdict(allowMysql, license("com.mysql:mysql-connector-j:9.7.0", MYSQL))).isEqualTo(Verdict.ALLOWED);
        assertThat(verdict(denyEpl, license("org.aspectj:aspectjweaver:1.9.25.1", "Eclipse Public License - v 2.0")))
                .isEqualTo(Verdict.DENIED);
    }

    @Test
    void 유효한_예외는_인정하고_만료된_예외는_다시_위반이다() {
        ComponentLicense mysql = license("com.mysql:mysql-connector-j:9.7.0", MYSQL);
        LicensePolicy valid = withException(new LicenseException("com.mysql:mysql-connector-j", "서버 내부에서만 실행", "2027-05-18"));
        LicensePolicy expired = withException(new LicenseException("com.mysql:mysql-connector-j", "서버 내부에서만 실행", "2026-11-17"));

        assertThat(verdict(valid, mysql)).isEqualTo(Verdict.ACCEPTED);
        assertThat(verdict(expired, mysql)).isEqualTo(Verdict.DENIED);
        assertThat(expired.evaluate(List.of(mysql), TODAY).passed()).isFalse();
    }

    @Test
    void 사유나_만료일이_없는_예외와_모르는_식별자는_설정_오류다() {
        LicensePolicy p = new LicensePolicy(null, null, List.of("Not-A-License"), null,
                List.of(new LicenseException("com.mysql:mysql-connector-j", "", "2027-01-01")));

        LicensePolicy.Result r = p.evaluate(List.of(), TODAY);

        assertThat(r.problems()).hasSize(2);
        assertThat(r.passed()).isFalse();
    }

    @Test
    void 정책_파일을_읽는다(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("licenses.yml");
        Files.writeString(file, """
                deny: [STRONG_COPYLEFT, NETWORK_COPYLEFT, UNKNOWN]
                review: [WEAK_COPYLEFT]
                exceptions:
                  - package: com.mysql:mysql-connector-j
                    reason: 서버 내부에서만 실행
                    expires: 2027-05-18
                """);

        LicensePolicy p = LicensePolicy.load(file);

        assertThat(p.deny()).contains(LicenseCategory.UNKNOWN);
        assertThat(verdict(p, license("g:custom:1", "Custom License"))).isEqualTo(Verdict.DENIED);
        assertThat(verdict(p, license("com.mysql:mysql-connector-j:9.7.0", MYSQL))).isEqualTo(Verdict.ACCEPTED);
    }

    private static LicensePolicy withException(LicenseException e) {
        return new LicensePolicy(LicensePolicy.DEFAULT.deny(), LicensePolicy.DEFAULT.review(), List.of(), List.of(), List.of(e));
    }
}
