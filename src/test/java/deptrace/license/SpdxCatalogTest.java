package deptrace.license;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

import deptrace.license.Pom.DeclaredLicense;

/** 테스트 값은 경매톡 배포 클래스패스의 POM에 실제로 적힌 표기를 옮겼다. */
class SpdxCatalogTest {

    private static String id(String name, String url) {
        return SpdxCatalog.identify(new DeclaredLicense(name, url)).map(SpdxCatalog.License::id).orElse(null);
    }

    @Test
    void 제각각인_Apache_표기를_하나로_모은다() {
        assertThat(id("The Apache Software License, Version 2.0", null)).isEqualTo("Apache-2.0");
        assertThat(id("Apache 2", null)).isEqualTo("Apache-2.0");
        assertThat(id("Apache License, version 2.0", null)).isEqualTo("Apache-2.0");
        assertThat(id(null, "https://www.apache.org/licenses/LICENSE-2.0.txt")).isEqualTo("Apache-2.0");
    }

    @Test
    void 이름으로_못_찾으면_URL로_찾는다() {
        assertThat(id("Some Custom Name", "http://www.opensource.org/licenses/mit-license.php")).isEqualTo("MIT");
    }

    @Test
    void 더_구체적인_URL을_우선한다() {
        // opensource.org/licenses/mit가 opensource.org/licenses/mit-0의 앞부분이라 짧은 패턴이 먼저 맞으면 MIT로 잘못 묶인다
        assertThat(id(null, "https://opensource.org/licenses/MIT-0")).isEqualTo("MIT-0");
        assertThat(id(null, "https://www.gnu.org/licenses/gpl-3.0.html")).isEqualTo("GPL-3.0-only");
    }

    @Test
    void 이름에만_있는_or_later와_예외_조항을_놓치지_않는다() {
        // hibernate-core: URL은 LGPL 2.1 원문과 같지만 이름은 "or later"
        assertThat(id("GNU Library General Public License v2.1 or later", "https://www.gnu.org/licenses/old-licenses/lgpl-2.1.html"))
                .isEqualTo("LGPL-2.1-or-later");
        // jakarta.*: Classpath 예외는 약한 카피레프트
        assertThat(SpdxCatalog.identify(new DeclaredLicense("GPL2 w/ CPE", "https://www.gnu.org/software/classpath/license.html")))
                .get().extracting(SpdxCatalog.License::category).isEqualTo(LicenseCategory.WEAK_COPYLEFT);
    }

    @Test
    void Universal_FOSS_예외는_비공개_서비스에_적용되지_않아_강한_카피레프트다() {
        SpdxCatalog.License mysql = SpdxCatalog.identify(new DeclaredLicense(
                "The GNU General Public License, v2 with Universal FOSS Exception, v1.0", null)).orElseThrow();

        assertThat(mysql.id()).isEqualTo("GPL-2.0-only WITH Universal-FOSS-exception-1.0");
        assertThat(mysql.category()).isEqualTo(LicenseCategory.STRONG_COPYLEFT);
    }

    @Test
    void 버전_없는_Apache와_모르는_표기는_추측하지_않는다() {
        assertThat(id("Apache License", null)).isNull();
        assertThat(id("Proprietary", null)).isNull();
    }

    @Test
    void 버전_없는_BSD는_허용형이지만_조항_수를_단정하지_않는다() {
        SpdxCatalog.License bsd = SpdxCatalog.identify(new DeclaredLicense("BSD License", null)).orElseThrow();

        assertThat(bsd.id()).isEqualTo("LicenseRef-BSD");
        assertThat(bsd.category()).isEqualTo(LicenseCategory.PERMISSIVE);
    }
}
