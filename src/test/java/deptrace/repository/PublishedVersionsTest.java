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
    void 현재_버전과_같은_변형을_고른다() {
        // 경매톡 guava 33.6.0-jre, GHSA-xxph-c9ww-hj94의 OSV 수정 버전 33.7.2는 변형 없이 배포되지 않는다
        PublishedVersions guava = module -> Optional.of(List.of(
                "33.6.0-android", "33.6.0-jre", "33.7.2-android", "33.7.2-jre", "33.8.0-android", "33.8.0-jre"));

        assertThat(guava.lowestPublishedAtLeast("com.google.guava:guava", "33.7.2", "33.6.0-jre")).contains("33.7.2-jre");
        assertThat(guava.lowestPublishedAtLeast("com.google.guava:guava", "33.7.2", "33.6.0-android")).contains("33.7.2-android");
        // 현재 버전을 모르면 기존처럼 Maven 순서상 가장 낮은 버전
        assertThat(guava.lowestPublishedAtLeast("com.google.guava:guava", "33.7.2")).contains("33.7.2-android");
    }

    @Test
    void 같은_변형이_없으면_다른_변형으로_넘어간다() {
        PublishedVersions v = module -> Optional.of(List.of("1.0.0-jre", "2.0.0-android"));

        assertThat(v.lowestPublishedAtLeast("g:a", "2.0.0", "1.0.0-jre")).contains("2.0.0-android");
    }

    @Test
    void 정식_표기와_사전_배포는_변형이_아니다() {
        assertThat(PublishedVersions.flavor("33.6.0-jre")).isEqualTo("jre");
        assertThat(PublishedVersions.flavor("12.8.1.jre11")).isEqualTo("jre11");
        assertThat(PublishedVersions.flavor("4.1.137.Final")).isEmpty();
        assertThat(PublishedVersions.flavor("2.2.6.RELEASE")).isEmpty();
        assertThat(PublishedVersions.flavor("10.1.59")).isEmpty();
        assertThat(PublishedVersions.flavor("2.0.0-RC2")).isEmpty();
        assertThat(PublishedVersions.flavor("v3-rev20260318-2.0.0")).isEmpty();
    }

    @Test
    void 변형_없는_버전은_변형_없는_후보를_우선한다() {
        PublishedVersions netty = module -> Optional.of(List.of("4.1.136.Final", "4.1.137.Final"));

        assertThat(netty.lowestPublishedAtLeast("io.netty:netty-codec", "4.1.137.Final", "4.1.114.Final")).contains("4.1.137.Final");
    }

    @Test
    void 조회할_수_없으면_빈_값이다() {
        assertThat(PublishedVersions.NONE.lowestPublishedAtLeast("g:a", "1.0")).isEmpty();
    }
}
