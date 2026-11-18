package deptrace.analysis;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import deptrace.graph.ResolvedGraph;

/**
 * 구성요소가 어떤 직접 의존성을 통해 들어왔는지 추적한다.
 *
 * <p>루트에서 대상까지의 모든 단순 경로는 그래프가 커지면 기하급수적으로 늘어난다(예: spring-core는 수십 개 경로).
 * 개발자가 실제로 조치할 수 있는 단위는 "어떤 직접 의존성이 끌고 왔는가"이므로,
 * 직접 의존성(1차 유입자)마다 대상까지의 최단 경로 하나만 BFS로 구한다. 비용은 O(직접 의존성 수 × (V + E)).
 */
public final class PathTracer {

    /** introducer: 빌드 스크립트의 직접 의존성, path: 루트 → introducer → … → 대상. */
    public record Introduction(String introducer, List<String> path) {
    }

    private PathTracer() {
    }

    public static List<Introduction> introductions(ResolvedGraph graph, String targetId) {
        List<Introduction> result = new ArrayList<>();
        for (String direct : graph.directDependencyIds()) {
            List<String> path = shortestPath(graph, direct, targetId);
            if (path != null) {
                path.add(0, graph.root());
                result.add(new Introduction(direct, List.copyOf(path)));
            }
        }
        result.sort(Comparator.comparingInt((Introduction i) -> i.path().size()).thenComparing(Introduction::introducer));
        return result;
    }

    /** from에서 to까지 제약 엣지를 제외한 최단 경로. 도달할 수 없으면 null. */
    static List<String> shortestPath(ResolvedGraph graph, String from, String to) {
        Map<String, String> parent = new HashMap<>();
        Deque<String> queue = new ArrayDeque<>();
        parent.put(from, null);
        queue.add(from);
        while (!queue.isEmpty()) {
            String current = queue.poll();
            if (current.equals(to)) {
                LinkedList<String> path = new LinkedList<>();
                for (String n = to; n != null; n = parent.get(n)) {
                    path.addFirst(n);
                }
                return path;
            }
            for (ResolvedGraph.Edge e : graph.dependencyEdgesFrom(current)) {
                if (!parent.containsKey(e.to())) {   // 방문 기록이 순환도 막는다
                    parent.put(e.to(), current);
                    queue.add(e.to());
                }
            }
        }
        return null;
    }
}
