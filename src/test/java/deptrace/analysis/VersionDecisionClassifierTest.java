package deptrace.analysis;

import static deptrace.GraphFixture.ROOT;
import static deptrace.GraphFixture.graph;
import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

import deptrace.analysis.VersionDecision.Kind;
import deptrace.graph.ResolvedGraph;

class VersionDecisionClassifierTest {

    @Test
    void 직접_선언이_다른_라이브러리의_더_높은_요청을_덮어쓰면_하향으로_분류한다() {
        // 경매톡 nimbus-jose-jwt: 직접 선언 9.37, Spring Security는 9.37.3 요청, dependency-management 규칙으로 9.37 선택
        ResolvedGraph g = graph()
                .node("org.springframework.security:spring-security-oauth2-jose:6.3.4")
                .node("com.nimbusds:nimbus-jose-jwt:9.37", "REQUESTED", "SELECTED_BY_RULE")
                .declared("com.nimbusds:nimbus-jose-jwt", "9.37")
                .edge(ROOT, "com.nimbusds:nimbus-jose-jwt:9.37", "com.nimbusds:nimbus-jose-jwt:9.37")
                .edge(ROOT, "org.springframework.security:spring-security-oauth2-jose", "org.springframework.security:spring-security-oauth2-jose:6.3.4")
                .edge("org.springframework.security:spring-security-oauth2-jose:6.3.4", "com.nimbusds:nimbus-jose-jwt:9.37.3", "com.nimbusds:nimbus-jose-jwt:9.37")
                .build();

        VersionDecision d = classify(g, "com.nimbusds:nimbus-jose-jwt:9.37");

        assertThat(d.kind()).isEqualTo(Kind.DIRECT_OVERRIDE);
        assertThat(d.downgraded()).isTrue();
        assertThat(d.explanation()).contains("9.37.3").contains("하향");
    }

    @Test
    void 직접_선언이_BOM_관리_버전과_다르면_덮어쓰기로_분류한다() {
        ResolvedGraph g = graph()
                .node("com.querydsl:querydsl-jpa:5.0.0", "REQUESTED", "SELECTED_BY_RULE")
                .declared("com.querydsl:querydsl-jpa", "5.0.0")
                .managed("com.querydsl:querydsl-jpa", "5.1.0")
                .edge(ROOT, "com.querydsl:querydsl-jpa:5.0.0", "com.querydsl:querydsl-jpa:5.0.0")
                .build();

        VersionDecision d = classify(g, "com.querydsl:querydsl-jpa:5.0.0");

        assertThat(d.kind()).isEqualTo(Kind.DIRECT_OVERRIDE);
        assertThat(d.managed()).isEqualTo("5.1.0");
        assertThat(d.downgraded()).isFalse();   // 요청 자체는 5.0.0뿐이므로 하향은 아니다
    }

    @Test
    void BOM이_요청_범위_밖의_버전을_고르면_범위_이탈을_표시한다() {
        ResolvedGraph g = graph()
                .node("com.nimbusds:oauth2-oidc-sdk:9.43.4")
                .node("net.minidev:json-smart:2.5.1", "REQUESTED", "SELECTED_BY_RULE")
                .managed("net.minidev:json-smart", "2.5.1")
                .edge(ROOT, "com.nimbusds:oauth2-oidc-sdk:9.43.4", "com.nimbusds:oauth2-oidc-sdk:9.43.4")
                .edge("com.nimbusds:oauth2-oidc-sdk:9.43.4", "net.minidev:json-smart:[1.3.3,2.4.10]", "net.minidev:json-smart:2.5.1")
                .build();

        VersionDecision d = classify(g, "net.minidev:json-smart:2.5.1");

        assertThat(d.kind()).isEqualTo(Kind.BOM_MANAGED);
        assertThat(d.outOfRange()).containsExactly("[1.3.3,2.4.10]");
    }

    @Test
    void BOM_규칙이_전이_요청보다_낮은_버전을_고르면_하향이다() {
        // firebase-admin 9.11.0은 httpclient5 5.6.4를 요청하지만 Spring Boot BOM이 5.5.2로 결정
        ResolvedGraph g = graph()
                .node("com.google.firebase:firebase-admin:9.11.0")
                .node("org.apache.httpcomponents.client5:httpclient5:5.5.2", "REQUESTED", "SELECTED_BY_RULE")
                .managed("org.apache.httpcomponents.client5:httpclient5", "5.5.2")
                .edge(ROOT, "com.google.firebase:firebase-admin:9.11.0", "com.google.firebase:firebase-admin:9.11.0")
                .edge("com.google.firebase:firebase-admin:9.11.0", "org.apache.httpcomponents.client5:httpclient5:5.6.4",
                        "org.apache.httpcomponents.client5:httpclient5:5.5.2")
                .build();

        VersionDecision d = classify(g, "org.apache.httpcomponents.client5:httpclient5:5.5.2");

        assertThat(d.kind()).isEqualTo(Kind.BOM_MANAGED);
        assertThat(d.downgraded()).isTrue();
    }

    @Test
    void 관리되지_않는_전이_의존성의_충돌은_충돌_해결로_분류한다() {
        ResolvedGraph g = graph()
                .node("com.mysql:mysql-connector-j:8.3.0")
                .node("com.google.cloud:google-cloud-storage:2.14.0")
                .node("com.google.protobuf:protobuf-java:3.25.1", "REQUESTED", "CONFLICT_RESOLUTION")
                .edge(ROOT, "com.mysql:mysql-connector-j", "com.mysql:mysql-connector-j:8.3.0")
                .edge(ROOT, "com.google.cloud:google-cloud-storage:2.14.0", "com.google.cloud:google-cloud-storage:2.14.0")
                .edge("com.mysql:mysql-connector-j:8.3.0", "com.google.protobuf:protobuf-java:3.25.1", "com.google.protobuf:protobuf-java:3.25.1")
                .edge("com.google.cloud:google-cloud-storage:2.14.0", "com.google.protobuf:protobuf-java:3.21.8", "com.google.protobuf:protobuf-java:3.25.1")
                .build();

        VersionDecision d = classify(g, "com.google.protobuf:protobuf-java:3.25.1");

        assertThat(d.kind()).isEqualTo(Kind.CONFLICT_RESOLUTION);
        assertThat(d.downgraded()).isFalse();
    }

    private static VersionDecision classify(ResolvedGraph g, String id) {
        return VersionDecisionClassifier.classify(g, g.node(id).orElseThrow());
    }
}
