package deptrace.graph;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import deptrace.model.Coordinate;

/**
 * 구성 하나의 해석 결과 그래프. 노드는 선택된 구성요소, 엣지는 "요청 → 선택" 관계다.
 */
public final class ResolvedGraph {

    /** coordinate가 비어 있으면 프로젝트 구성요소(루트 등)다. */
    public record Node(String id, Coordinate coordinate, List<GraphExport.Reason> reasons) {

        public Set<String> causes() {
            return reasons.stream().map(GraphExport.Reason::cause).collect(Collectors.toCollection(LinkedHashSet::new));
        }

        public boolean isComponent() {
            return coordinate != null;
        }
    }

    /** requestedVersion은 범위·빈 값(BOM 관리)일 수 있다. */
    public record Edge(String from, String to, String requestedModule, String requestedVersion, boolean constraint) {
    }

    private final GraphExport data;
    private final Map<String, Node> nodes = new LinkedHashMap<>();
    private final Map<String, List<Edge>> outgoing = new LinkedHashMap<>();
    private final Map<String, List<Edge>> incoming = new LinkedHashMap<>();
    private final List<GraphExport.EdgeData> unresolved = new ArrayList<>();

    private ResolvedGraph(GraphExport data) {
        this.data = data;
        data.nodes().forEach((id, n) -> nodes.put(id,
                new Node(id, Coordinate.parse(id).orElse(null), n.reasons() == null ? List.of() : n.reasons())));
        for (GraphExport.EdgeData e : data.edges()) {
            if (e.unresolved() || e.to() == null) {
                unresolved.add(e);
                continue;
            }
            String[] req = e.requested().split(":", 3);
            Edge edge = new Edge(e.from(), e.to(),
                    req.length >= 2 ? req[0] + ":" + req[1] : e.requested(),
                    req.length == 3 ? req[2] : null,
                    e.constraint());
            outgoing.computeIfAbsent(e.from(), k -> new ArrayList<>()).add(edge);
            incoming.computeIfAbsent(e.to(), k -> new ArrayList<>()).add(edge);
        }
    }

    public static ResolvedGraph of(GraphExport data) {
        return new ResolvedGraph(data);
    }

    public String configuration() {
        return data.configuration();
    }

    public String project() {
        return data.project();
    }

    /** 이전 형식의 추출 파일에는 없을 수 있다(null). */
    public GraphExport data() {
        return data;
    }

    public String root() {
        return data.root();
    }

    public Optional<Node> node(String id) {
        return Optional.ofNullable(nodes.get(id));
    }

    public List<Node> components() {
        return nodes.values().stream().filter(Node::isComponent).toList();
    }

    public Optional<Node> findByModule(String module) {
        return components().stream().filter(n -> n.coordinate().module().equals(module)).findFirst();
    }

    /** 실제 유입 경로가 되는 엣지만 반환한다. BOM/platform 제약은 버전에 영향을 줄 뿐 구성요소를 끌어오지 않는다. */
    public List<Edge> dependencyEdgesFrom(String id) {
        return outgoing.getOrDefault(id, List.of()).stream().filter(e -> !e.constraint()).toList();
    }

    public List<Edge> dependencyEdgesTo(String id) {
        return incoming.getOrDefault(id, List.of()).stream().filter(e -> !e.constraint()).toList();
    }

    /** 루트가 직접 의존하는 구성요소 ID(빌드 스크립트의 직접 의존성). */
    public List<String> directDependencyIds() {
        return dependencyEdgesFrom(root()).stream().map(Edge::to).distinct().toList();
    }

    /** 빌드 스크립트에 버전과 함께 직접 선언된 경우 그 버전. */
    public Optional<String> declaredVersion(String module) {
        if (data.directDependencies() == null) {
            return Optional.empty();
        }
        return data.directDependencies().stream()
                .filter(d -> module.equals(d.group() + ":" + d.name()))
                .map(GraphExport.DeclaredDependency::version)
                .filter(v -> v != null && !v.isBlank())
                .findFirst();
    }

    /** Spring dependency-management 플러그인(BOM)이 관리하는 버전. */
    public Optional<String> managedVersion(String module) {
        Map<String, String> managed = data.managedVersions();
        return managed == null ? Optional.empty() : Optional.ofNullable(managed.get(module));
    }

    public List<GraphExport.EdgeData> unresolved() {
        return Collections.unmodifiableList(unresolved);
    }
}
