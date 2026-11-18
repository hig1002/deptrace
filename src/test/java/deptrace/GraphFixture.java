package deptrace;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import deptrace.graph.GraphExport;
import deptrace.graph.ResolvedGraph;

/** 테스트용 해석 그래프를 init script 출력과 같은 구조로 만든다. */
public final class GraphFixture {

    public static final String ROOT = "root project :";

    private final String configuration;
    private final Map<String, GraphExport.NodeData> nodes = new LinkedHashMap<>();
    private final List<GraphExport.EdgeData> edges = new ArrayList<>();
    private final List<GraphExport.DeclaredDependency> declared = new ArrayList<>();
    private final Map<String, String> managed = new LinkedHashMap<>();

    private GraphFixture(String configuration) {
        this.configuration = configuration;
        nodes.put(ROOT, new GraphExport.NodeData(null, null, List.of(new GraphExport.Reason("ROOT", "root"))));
    }

    public static GraphFixture graph() {
        return new GraphFixture("productionRuntimeClasspath");
    }

    public static GraphFixture graph(String configuration) {
        return new GraphFixture(configuration);
    }

    /** 노드 추가. causes는 Gradle 선택 사유(REQUESTED, SELECTED_BY_RULE ...). */
    public GraphFixture node(String id, String... causes) {
        String[] p = id.split(":");
        List<GraphExport.Reason> reasons = new ArrayList<>();
        for (String c : causes.length == 0 ? new String[]{"REQUESTED"} : causes) {
            reasons.add(new GraphExport.Reason(c, c.equals("CONFLICT_RESOLUTION") ? "between versions" : c.toLowerCase()));
        }
        nodes.put(id, new GraphExport.NodeData(p[0] + ":" + p[1], p[2], reasons));
        return this;
    }

    /** from이 requested 표기로 요청했고 to가 선택됨. */
    public GraphFixture edge(String from, String requested, String to) {
        edges.add(new GraphExport.EdgeData(from, requested, to, false, false));
        return this;
    }

    public GraphFixture constraintEdge(String from, String requested, String to) {
        edges.add(new GraphExport.EdgeData(from, requested, to, true, false));
        return this;
    }

    /** 빌드 스크립트 직접 선언 (version이 null이면 BOM 관리). */
    public GraphFixture declared(String module, String version) {
        String[] p = module.split(":");
        declared.add(new GraphExport.DeclaredDependency(p[0], p[1], version, "implementation"));
        return this;
    }

    public GraphFixture managed(String module, String version) {
        managed.put(module, version);
        return this;
    }

    public ResolvedGraph build() {
        return ResolvedGraph.of(new GraphExport("deptrace-graph/1", ":", configuration, "8.14.3", ROOT,
                declared, managed, nodes, edges));
    }
}
