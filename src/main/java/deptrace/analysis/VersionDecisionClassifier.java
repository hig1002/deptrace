package deptrace.analysis;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import deptrace.analysis.VersionDecision.Kind;
import deptrace.graph.ResolvedGraph;
import deptrace.model.Versions;

/**
 * 요청 버전(엣지), 선택 버전과 선택 사유(노드), 직접 선언·BOM 관리 버전(빌드 설정)을 비교해 버전 결정 원인을 분류한다.
 *
 * <p>Gradle 기본 충돌 해결은 항상 가장 높은 요청 버전을 고른다. 반면 Spring dependency-management 플러그인은
 * 규칙(SELECTED_BY_RULE)으로 버전을 덮어쓰기 때문에 요청보다 낮은 버전이 선택되는 "하향"이 생길 수 있다.
 * 이 클래스는 그 차이를 드러내는 것이 목적이다.
 */
public final class VersionDecisionClassifier {

    private VersionDecisionClassifier() {
    }

    public static VersionDecision classify(ResolvedGraph graph, ResolvedGraph.Node node) {
        String module = node.coordinate().module();
        String selected = node.coordinate().version();
        String declared = graph.declaredVersion(module).orElse(null);
        String managed = graph.managedVersion(module).orElse(null);
        Set<String> causes = node.causes();

        List<ResolvedGraph.Edge> in = graph.dependencyEdgesTo(node.id());
        boolean direct = in.stream().anyMatch(e -> e.from().equals(graph.root()));
        List<String> requested = in.stream().map(ResolvedGraph.Edge::requestedVersion)
                .filter(Objects::nonNull).distinct().toList();
        List<String> transitiveRequested = in.stream().filter(e -> !e.from().equals(graph.root()))
                .map(ResolvedGraph.Edge::requestedVersion).filter(Versions::isExact).distinct().toList();

        boolean downgraded = requested.stream().filter(Versions::isExact)
                .anyMatch(r -> Versions.compare(r, selected) > 0);
        List<String> outOfRange = requested.stream()
                .filter(Versions::isRange)
                .filter(r -> !Versions.rangeContains(r, selected))
                .toList();

        Kind kind;
        if (direct && declared != null && declared.equals(selected)) {
            boolean overridesManaged = managed != null && !managed.equals(declared);
            boolean overridesTransitive = transitiveRequested.stream().anyMatch(r -> !r.equals(declared));
            kind = overridesManaged || overridesTransitive ? Kind.DIRECT_OVERRIDE : Kind.DIRECT;
        } else if (causes.contains("FORCED")) {
            kind = Kind.FORCED;
        } else if (causes.contains("SELECTED_BY_RULE") && selected.equals(managed)) {
            kind = Kind.BOM_MANAGED;
        } else if (causes.contains("CONFLICT_RESOLUTION")) {
            kind = Kind.CONFLICT_RESOLUTION;
        } else if (causes.contains("CONSTRAINT")) {
            kind = Kind.CONSTRAINT;
        } else {
            kind = Kind.TRANSITIVE;
        }

        boolean maven = graph.data() != null && graph.data().isMaven();
        return new VersionDecision(kind, selected, declared, managed, requested, downgraded, outOfRange,
                explain(kind, node, declared, managed, transitiveRequested, downgraded, outOfRange, maven));
    }

    private static String explain(Kind kind, ResolvedGraph.Node node, String declared, String managed,
                                  List<String> transitiveRequested, boolean downgraded, List<String> outOfRange, boolean maven) {
        String selected = node.coordinate().version();
        List<String> parts = new ArrayList<>();
        switch (kind) {
            case DIRECT -> parts.add((maven ? "pom.xml" : "빌드 스크립트") + "에 직접 선언한 버전(" + declared + ")이 선택됨");
            case DIRECT_OVERRIDE -> {
                List<String> overridden = new ArrayList<>();
                if (managed != null && !managed.equals(declared)) {
                    overridden.add((maven ? "dependencyManagement 관리 버전 " : "BOM 관리 버전 ") + managed);
                }
                List<String> others = transitiveRequested.stream().filter(r -> !r.equals(declared)).toList();
                if (!others.isEmpty()) {
                    overridden.add("다른 라이브러리의 요청 " + String.join(", ", others));
                }
                parts.add("직접 선언한 버전(" + declared + ")이 " + String.join("과 ", overridden) + "보다 우선 적용됨");
            }
            case BOM_MANAGED -> parts.add((maven ? "dependencyManagement(부모 POM·BOM import)가" : "Spring Boot BOM(dependency-management 플러그인)이")
                    + " 관리 버전 " + managed + "으로 결정"
                    + (transitiveRequested.isEmpty() || transitiveRequested.equals(List.of(selected))
                    ? "" : " (전이 요청: " + String.join(", ", transitiveRequested) + ")"));
            // Gradle은 충돌 시 항상 가장 높은 버전, Maven은 루트에 가장 가까운 선언(nearest-wins)을 고른다
            case CONFLICT_RESOLUTION -> parts.add(maven
                    ? "Maven nearest-wins: 루트에 더 가까운 경로의 버전이 선택됨 (" + describe(node, "CONFLICT_RESOLUTION") + ")"
                    : "버전 충돌 중 가장 높은 버전 선택 (" + describe(node, "CONFLICT_RESOLUTION") + ")");
            case CONSTRAINT -> parts.add("platform/constraint 제약으로 결정");
            case FORCED -> parts.add("force 설정으로 강제됨");
            case TRANSITIVE -> parts.add("전이 의존성이 요청한 버전 그대로 선택됨");
        }
        if (downgraded) {
            parts.add("요청된 더 높은 버전 대신 낮은 버전이 선택된 하향");
        }
        if (!outOfRange.isEmpty()) {
            parts.add("요청 범위 " + String.join(", ", outOfRange) + " 밖의 버전");
        }
        return String.join(" · ", parts);
    }

    private static String describe(ResolvedGraph.Node node, String cause) {
        return node.reasons().stream()
                .filter(r -> cause.equals(r.cause()))
                .map(r -> r.description())
                .findFirst().orElse(cause);
    }
}
