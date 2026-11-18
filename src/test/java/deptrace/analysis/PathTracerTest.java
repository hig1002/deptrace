package deptrace.analysis;

import static deptrace.GraphFixture.ROOT;
import static deptrace.GraphFixture.graph;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.junit.jupiter.api.Test;

import deptrace.graph.ResolvedGraph;

class PathTracerTest {

    private static final String A = "g:a:1";
    private static final String B = "g:b:1";
    private static final String C = "g:c:1";
    private static final String D = "g:d:1";
    private static final String T = "g:target:1";

    @Test
    void 직접_의존성마다_대상까지의_최단_경로를_하나씩_찾는다() {
        // A → B → T, A → C → D → T (A 기준 최단은 A → B → T), D → T (D도 직접 의존성)
        ResolvedGraph g = graph()
                .node(A).node(B).node(C).node(D).node(T)
                .edge(ROOT, "g:a:1", A).edge(ROOT, "g:d:1", D)
                .edge(A, "g:b:1", B).edge(A, "g:c:1", C)
                .edge(B, "g:target:1", T).edge(C, "g:d:1", D).edge(D, "g:target:1", T)
                .build();

        List<PathTracer.Introduction> intro = PathTracer.introductions(g, T);

        assertThat(intro).extracting(PathTracer.Introduction::introducer).containsExactly(D, A);
        assertThat(intro.get(0).path()).containsExactly(ROOT, D, T);
        assertThat(intro.get(1).path()).containsExactly(ROOT, A, B, T);
    }

    @Test
    void 제약_엣지는_유입_경로로_보지_않는다() {
        // platform(BOM)이 T의 버전을 제약하지만 T를 끌어오지는 않는다
        ResolvedGraph g = graph()
                .node("g:platform:1").node(A).node(T)
                .edge(ROOT, "g:platform:1", "g:platform:1")
                .constraintEdge("g:platform:1", "g:target:1", T)
                .edge(ROOT, "g:a:1", A).edge(A, "g:target:1", T)
                .build();

        assertThat(PathTracer.introductions(g, T)).extracting(PathTracer.Introduction::introducer).containsExactly(A);
    }

    @Test
    void 순환이_있어도_종료한다() {
        ResolvedGraph g = graph()
                .node(A).node(B).node(T)
                .edge(ROOT, "g:a:1", A)
                .edge(A, "g:b:1", B).edge(B, "g:a:1", A).edge(B, "g:target:1", T)
                .build();

        assertThat(PathTracer.introductions(g, T).get(0).path()).containsExactly(ROOT, A, B, T);
    }

    @Test
    void 도달할_수_없으면_빈_목록이다() {
        ResolvedGraph g = graph().node(A).node(T).edge(ROOT, "g:a:1", A).build();

        assertThat(PathTracer.introductions(g, T)).isEmpty();
    }
}
