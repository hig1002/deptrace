package deptrace.maven;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;

import org.junit.jupiter.api.Test;

import deptrace.analysis.Remediation;
import deptrace.analysis.VersionDecision;
import deptrace.analysis.VersionDecisionClassifier;
import deptrace.graph.GraphExport;
import deptrace.graph.ResolvedGraph;

/** 트리 조각은 spring-batch-extensions(spring-batch-notion·neo4j·bigquery)의 실제 dependency:tree -Dverbose 출력을 줄였다. */
class MavenTreeParserTest {

    private static final String TREE = """
            org.springframework.batch.extensions:spring-batch-neo4j:jar:0.2.0-SNAPSHOT
            +- org.springframework.batch:spring-batch-infrastructure:jar:6.0.2:compile
            |  \\- org.springframework:spring-core:jar:7.0.5:compile (version managed from 7.0.3)
            +- org.neo4j.driver:neo4j-java-driver:jar:6.0.2:compile
            |  \\- org.neo4j.bolt:neo4j-bolt-connection-netty:jar:10.0.1:compile
            |     +- io.netty:netty-handler:jar:4.1.127.Final:compile (version managed from 4.2.2.Final)
            |     \\- (org.springframework:spring-core:jar:7.0.5:compile - version managed from 7.0.1; omitted for duplicate)
            +- org.apache.commons:commons-configuration2:jar:2.11.0:compile
            |  \\- (org.apache.commons:commons-text:jar:1.11.0:compile - omitted for conflict with 1.10.0)
            +- org.apache.commons:commons-text:jar:1.10.0:compile
            +- io.netty:netty-tcnative-boringssl-static:jar:linux-x86_64:2.0.70.Final:runtime
            \\- org.wiremock.integrations:wiremock-spring-boot:jar:4.2.0:test
               \\- org.eclipse.jetty.ee10:jetty-ee10-servlet:jar:12.1.6:test
            """;

    private static final List<MavenTreeParser.Declared> DECLARED = List.of(
            new MavenTreeParser.Declared("org.springframework.batch:spring-batch-infrastructure", false),
            new MavenTreeParser.Declared("org.neo4j.driver:neo4j-java-driver", true),
            new MavenTreeParser.Declared("org.apache.commons:commons-configuration2", true),
            new MavenTreeParser.Declared("org.apache.commons:commons-text", true));

    private static ResolvedGraph graph(String configuration) {
        return MavenTreeParser.parse(TREE, DECLARED, null).stream()
                .filter(g -> g.configuration().equals(configuration)).map(ResolvedGraph::of).findFirst().orElseThrow();
    }

    @Test
    void 줄의_깊이와_주석을_읽는다() {
        MavenTreeParser.Line conflict = MavenTreeParser.parseLine(
                "|  \\- (org.apache.commons:commons-text:jar:1.11.0:compile - omitted for conflict with 1.10.0)");
        MavenTreeParser.Line managed = MavenTreeParser.parseLine(
                "|     +- io.netty:netty-handler:jar:4.1.127.Final:compile (version managed from 4.2.2.Final)");
        MavenTreeParser.Line classifier = MavenTreeParser.parseLine(
                "+- io.netty:netty-tcnative-boringssl-static:jar:linux-x86_64:2.0.70.Final:runtime");

        assertThat(conflict.depth()).isEqualTo(2);
        assertThat(conflict.omitted()).isTrue();
        assertThat(conflict.selected()).isEqualTo("1.10.0");
        assertThat(conflict.requested()).isEqualTo("1.11.0");
        assertThat(managed.depth()).isEqualTo(3);
        assertThat(managed.requested()).isEqualTo("4.2.2.Final");
        assertThat(managed.selected()).isEqualTo("4.1.127.Final");
        assertThat(classifier.version()).isEqualTo("2.0.70.Final");
        assertThat(classifier.scope()).isEqualTo("runtime");
    }

    @Test
    void 실행_구성은_compile과_runtime만_담는다() {
        ResolvedGraph runtime = graph(MavenTreeParser.RUNTIME);
        ResolvedGraph test = graph(MavenTreeParser.TEST);

        assertThat(runtime.components()).extracting(n -> n.coordinate().module())
                .contains("io.netty:netty-tcnative-boringssl-static")
                .doesNotContain("org.wiremock.integrations:wiremock-spring-boot", "org.eclipse.jetty.ee10:jetty-ee10-servlet");
        assertThat(test.components()).extracting(n -> n.coordinate().module())
                .contains("org.eclipse.jetty.ee10:jetty-ee10-servlet");
        assertThat(runtime.data().isMaven()).isTrue();
    }

    @Test
    void nearest_wins_하향을_드러낸다() {
        ResolvedGraph g = graph(MavenTreeParser.RUNTIME);
        ResolvedGraph.Node text = g.findByModule("org.apache.commons:commons-text").orElseThrow();

        VersionDecision d = VersionDecisionClassifier.classify(g, text);

        // 직접 선언(1.10.0)이 commons-configuration2의 요청 1.11.0보다 루트에 가까워 선택됨
        assertThat(d.kind()).isEqualTo(VersionDecision.Kind.DIRECT_OVERRIDE);
        assertThat(d.downgraded()).isTrue();
        assertThat(d.requestedVersions()).contains("1.11.0");
    }

    @Test
    void dependencyManagement가_다른_라인으로_하향시킨_것을_분류한다() {
        ResolvedGraph g = graph(MavenTreeParser.RUNTIME);
        ResolvedGraph.Node netty = g.findByModule("io.netty:netty-handler").orElseThrow();

        VersionDecision d = VersionDecisionClassifier.classify(g, netty);

        assertThat(d.kind()).isEqualTo(VersionDecision.Kind.BOM_MANAGED);
        assertThat(d.downgraded()).isTrue();
        assertThat(d.explanation()).contains("dependencyManagement").doesNotContain("Spring Boot BOM(dependency-management 플러그인)");
        // 조치도 Gradle 문법이 아니라 pom.xml 기준으로 안내한다
        Remediation r = Remediation.advise(d, true, "4.1.130.Final", true, false, List.of(), "io.netty:netty-handler",
                List.of("org.neo4j.driver:neo4j-java-driver:6.0.2"), true);
        assertThat(r.advice()).contains("<properties>").doesNotContain("constraints {");
    }

    @Test
    void 버전_없이_선언한_직접_의존성은_관리_버전으로_본다() {
        ResolvedGraph g = graph(MavenTreeParser.RUNTIME);

        VersionDecision infra = VersionDecisionClassifier.classify(g, g.findByModule("org.springframework.batch:spring-batch-infrastructure").orElseThrow());
        VersionDecision driver = VersionDecisionClassifier.classify(g, g.findByModule("org.neo4j.driver:neo4j-java-driver").orElseThrow());

        assertThat(infra.kind()).isEqualTo(VersionDecision.Kind.BOM_MANAGED);
        assertThat(driver.kind()).isEqualTo(VersionDecision.Kind.DIRECT);
    }

    @Test
    void 생략된_중복은_엣지만_추가한다() {
        ResolvedGraph g = graph(MavenTreeParser.RUNTIME);
        ResolvedGraph.Node core = g.findByModule("org.springframework:spring-core").orElseThrow();

        assertThat(g.components()).filteredOn(n -> n.coordinate().module().equals("org.springframework:spring-core")).hasSize(1);
        assertThat(g.dependencyEdgesTo(core.id())).extracting(ResolvedGraph.Edge::requestedVersion).containsExactlyInAnyOrder("7.0.3", "7.0.1");
    }

    @Test
    void 콘솔_접두어를_떼고_여러_모듈_출력은_거부한다() {
        String console = TREE.lines().map(l -> "[INFO] " + l).reduce((a, b) -> a + "\n" + b).orElseThrow();
        List<GraphExport> parsed = MavenTreeParser.parse(console, DECLARED, null);
        assertThat(parsed).hasSize(2);

        assertThatThrownBy(() -> MavenTreeParser.parse(TREE + "org.example:other:jar:1.0\n", DECLARED, null))
                .hasMessageContaining("모듈이 둘 이상");
    }

    @Test
    void pom_xml의_직접_선언에서_버전_유무를_읽는다() {
        List<MavenTreeParser.Declared> d = PomDeclarations.parse("""
                <project>
                  <dependencyManagement><dependencies>
                    <dependency><groupId>x</groupId><artifactId>managed-only</artifactId><version>1</version></dependency>
                  </dependencies></dependencyManagement>
                  <dependencies>
                    <dependency><groupId>org.neo4j.driver</groupId><artifactId>neo4j-java-driver</artifactId><version>${neo4j.version}</version></dependency>
                    <dependency><groupId>org.springframework.batch</groupId><artifactId>spring-batch-infrastructure</artifactId></dependency>
                  </dependencies>
                </project>
                """);

        assertThat(d).containsExactly(
                new MavenTreeParser.Declared("org.neo4j.driver:neo4j-java-driver", true),
                new MavenTreeParser.Declared("org.springframework.batch:spring-batch-infrastructure", false));
    }
}
