package deptrace.repository;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.Test;

class PublishedVersionsTest {

    @Test
    void 수정_버전이_배포되지_않았으면_그_이상의_가장_낮은_정식_버전을_고른다() {
        PublishedVersions tomcat = module -> Optional.of(List.of("10.1.55", "10.1.57", "10.1.59", "10.1.60", "11.0.0-M1"));

        assertThat(tomcat.lowestPublishedAtLeast("org.apache.tomcat.embed:tomcat-embed-core", "10.1.58")).contains("10.1.59");
        assertThat(tomcat.lowestPublishedAtLeast("org.apache.tomcat.embed:tomcat-embed-core", "10.1.57")).contains("10.1.57");
    }

    @Test
    void 사전_배포_버전은_건너뛴다() {
        PublishedVersions v = module -> Optional.of(List.of("2.0.0-M1", "2.0.0-RC2", "2.0.0.Beta1", "2.0.0", "2.0.1-SNAPSHOT"));

        assertThat(v.lowestPublishedAtLeast("g:a", "1.9.9")).contains("2.0.0");
        assertThat(v.lowestPublishedAtLeast("g:a", "2.0.0-M1")).contains("2.0.0-M1");  // 수정 버전 자체가 사전 배포면 허용
    }

    @Test
    void 정식_버전_한정자는_사전_배포로_보지_않는다() {
        assertThat(PublishedVersions.PRE_RELEASE.matcher("4.1.137.Final").matches()).isFalse();
        assertThat(PublishedVersions.PRE_RELEASE.matcher("2.2.6.RELEASE").matches()).isFalse();
        assertThat(PublishedVersions.PRE_RELEASE.matcher("v3-rev20260318-2.0.0").matches()).isFalse();
        assertThat(PublishedVersions.PRE_RELEASE.matcher("6.0.0.M1").matches()).isTrue();
    }

    @Test
    void 조회할_수_없으면_빈_값이다() {
        assertThat(PublishedVersions.NONE.lowestPublishedAtLeast("g:a", "1.0")).isEmpty();
    }
}
