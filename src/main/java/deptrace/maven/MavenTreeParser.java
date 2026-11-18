package deptrace.maven;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import deptrace.graph.GraphExport;
import deptrace.graph.GraphExport.DeclaredDependency;
import deptrace.graph.GraphExport.EdgeData;
import deptrace.graph.GraphExport.NodeData;
import deptrace.graph.GraphExport.Reason;

/**
 * Maven의 {@code dependency:tree -Dverbose} 출력을 DepTrace 해석 그래프로 바꾼다.
 *
 * <p>해석은 Maven이 한다(ADR 0001과 같은 원칙). 이 클래스는 Maven이 출력에 남긴 결정을 그대로 옮길 뿐이다.
 * <ul>
 *   <li>{@code (g:a:jar:2.0:compile - omitted for conflict with 3.0)}: nearest-wins로 다른 경로의 3.0이 선택됨.
 *       루트에 가까운 선언이 이기므로, Gradle(항상 최고 버전)과 달리 더 낮은 버전이 선택되는 하향이 생길 수 있다.</li>
 *   <li>{@code (version managed from 1.0)}: dependencyManagement(부모 POM, BOM import)가 요청 버전 1.0을 덮어씀.</li>
 *   <li>{@code omitted for duplicate}: 같은 버전이 이미 선택됨. 엣지만 추가한다.</li>
 * </ul>
 *
 * <p>구성은 두 개를 만든다. {@code maven:runtime}은 compile·runtime 범위(실행 jar에 들어가는 것),
 * {@code maven:test}는 provided·test를 포함한 전체다.
 */
public final class MavenTreeParser {

    public static final String RUNTIME = "maven:runtime";
    public static final String TEST = "maven:test";

    private static final Set<String> RUNTIME_SCOPES = Set.of("compile", "runtime");
    private static final Set<String> ALL_SCOPES = Set.of("compile", "runtime", "provided", "test", "system");

    private static final Pattern MANAGED_FROM = Pattern.compile("version managed from ([^;)\\s]+)");
    private static final Pattern CONFLICT_WITH = Pattern.compile("omitted for conflict with ([^;)\\s]+)");

    /** 트리 한 줄. selected는 Maven이 최종 선택한 버전(충돌로 생략된 줄이면 이긴 쪽 버전). */
    record Line(int depth, String group, String artifact, String version, String scope, String managedFrom,
                String conflictWith, boolean omitted, boolean cycle, boolean optional) {

        String module() {
            return group + ":" + artifact;
        }

        String selected() {
            return conflictWith != null ? conflictWith : version;
        }

        /** 이 경로가 원래 요청한 버전: dependencyManagement가 덮어썼다면 그 전 버전. */
        String requested() {
            return managedFrom != null ? managedFrom : version;
        }
    }

    /** 직접 선언 정보(pom.xml). versionDeclared=false면 dependencyManagement에서 버전을 받는다. */
    public record Declared(String module, boolean versionDeclared) {
    }

    private MavenTreeParser() {
    }

    /** 트리 출력 하나(모듈 하나)를 두 구성의 그래프로 바꾼다. */
    public static List<GraphExport> parse(String tree, List<Declared> declared, String mavenVersion) {
        List<String> lines = tree.lines().map(MavenTreeParser::stripLogPrefix).filter(l -> !l.isBlank()).toList();
        if (lines.isEmpty()) {
            throw new IllegalArgumentException("트리 출력이 비어 있습니다");
        }
        String[] root = lines.get(0).trim().split(":");
        if (root.length < 4) {
            throw new IllegalArgumentException("첫 줄이 루트 좌표가 아닙니다: " + lines.get(0));
        }
        List<Line> parsed = new ArrayList<>();
        for (int i = 1; i < lines.size(); i++) {
            if (depthOf(lines.get(i)) == 0) {
                throw new IllegalArgumentException("모듈이 둘 이상인 출력입니다. 모듈마다 따로 내보내세요: " + lines.get(i));
            }
            parsed.add(parseLine(lines.get(i)));
        }
        String group = root[0];
        String artifact = root[1];
        String version = root[root.length - 1];
        return List.of(
                build(parsed, RUNTIME_SCOPES, RUNTIME, group, artifact, version, declared, mavenVersion),
                build(parsed, ALL_SCOPES, TEST, group, artifact, version, declared, mavenVersion));
    }

    private static GraphExport build(List<Line> lines, Set<String> scopes, String configuration, String group, String artifact,
                                     String version, List<Declared> declared, String mavenVersion) {
        String rootId = "root project " + artifact;
        Map<String, List<Reason>> reasons = new LinkedHashMap<>();
        Map<String, String> moduleOf = new LinkedHashMap<>();
        Set<String> present = new LinkedHashSet<>();
        List<EdgeData> edges = new ArrayList<>();
        Map<String, String> managed = new LinkedHashMap<>();
        reasons.put(rootId, new ArrayList<>(List.of(new Reason("ROOT", "root"))));

        Map<String, Declared> declaredByModule = new LinkedHashMap<>();
        declared.forEach(d -> declaredByModule.put(d.module(), d));

        // 깊이별 현재 부모. null이면 그 가지는 이 구성에 포함되지 않는다
        List<String> parents = new ArrayList<>();
        parents.add(rootId);
        for (Line l : lines) {
            while (parents.size() > l.depth()) {
                parents.remove(parents.size() - 1);
            }
            String parent = parents.isEmpty() ? null : parents.get(parents.size() - 1);
            boolean included = parent != null && scopes.contains(l.scope());
            String id = l.module() + ":" + l.selected();
            if (included && !l.cycle()) {
                edges.add(new EdgeData(parent, l.module() + ":" + l.requested(), id, false, false));
                List<Reason> rs = reasons.computeIfAbsent(id, k -> new ArrayList<>());
                moduleOf.put(id, l.module());
                addOnce(rs, "REQUESTED", "requested");
                if (l.managedFrom() != null) {
                    managed.put(l.module(), l.version());
                    if (!l.managedFrom().equals(l.version())) {
                        addOnce(rs, "SELECTED_BY_RULE", "dependencyManagement: " + l.managedFrom() + " → " + l.version());
                    }
                }
                if (l.conflictWith() != null) {
                    addOnce(rs, "CONFLICT_RESOLUTION", "nearest-wins: " + l.version() + " 요청보다 루트에 가까운 " + l.conflictWith() + " 선택");
                }
                if (!l.omitted()) {
                    present.add(id);
                }
                // 직접 의존성인데 pom.xml에 버전이 없으면 dependencyManagement가 정한 버전이다
                Declared d = declaredByModule.get(l.module());
                if (l.depth() == 1 && d != null && !d.versionDeclared()) {
                    managed.put(l.module(), l.selected());
                    addOnce(rs, "SELECTED_BY_RULE", "dependencyManagement: 직접 선언에 버전 없음");
                }
            }
            // 생략된 줄은 자식이 없다. 포함되지 않은 가지의 자식도 포함하지 않는다
            parents.add(included && !l.omitted() ? id : null);
        }

        Map<String, NodeData> nodes = new LinkedHashMap<>();
        nodes.put(rootId, new NodeData(null, null, reasons.get(rootId)));
        for (String id : present) {
            int i = id.lastIndexOf(':');
            nodes.put(id, new NodeData(moduleOf.get(id), id.substring(i + 1), List.copyOf(reasons.get(id))));
        }
        // 충돌로 생략된 줄이 가리키는 승자가 이 구성에 없으면(다른 범위에서만 선택됨) 엣지를 해석 실패로 둔다
        List<EdgeData> resolved = edges.stream()
                .map(e -> nodes.containsKey(e.to()) ? e : new EdgeData(e.from(), e.requested(), null, false, true))
                .toList();

        List<DeclaredDependency> direct = new ArrayList<>();
        for (Line l : lines) {
            if (l.depth() == 1 && !l.omitted() && scopes.contains(l.scope())) {
                Declared d = declaredByModule.get(l.module());
                String v = d == null || d.versionDeclared() ? l.version() : null;
                direct.add(new DeclaredDependency(l.group(), l.artifact(), v, "pom.xml"));
            }
        }
        return new GraphExport("deptrace-graph/1", ":", artifact, group, version, configuration, null, rootId,
                direct, managed, nodes, resolved, "maven");
    }

    private static void addOnce(List<Reason> rs, String cause, String description) {
        if (rs.stream().noneMatch(r -> r.cause().equals(cause))) {
            rs.add(new Reason(cause, description));
        }
    }

    static Line parseLine(String raw) {
        int depth = depthOf(raw);
        String content = raw.substring(depth * 3).trim();
        boolean omitted = content.startsWith("(") && content.endsWith(")");
        String annotations = "";
        if (omitted) {
            content = content.substring(1, content.length() - 1);
            int dash = content.indexOf(" - ");
            if (dash >= 0) {
                annotations = content.substring(dash + 3);
                content = content.substring(0, dash);
            }
        } else {
            int paren = content.indexOf(" (");
            if (paren >= 0) {
                annotations = content.substring(paren + 2, content.lastIndexOf(')'));
                content = content.substring(0, paren);
            }
        }
        String[] p = content.trim().split(":");
        // g:a:type:version:scope 또는 g:a:type:classifier:version:scope
        if (p.length < 5) {
            throw new IllegalArgumentException("좌표를 해석할 수 없습니다: " + raw);
        }
        String scope = p[p.length - 1];
        String version = p[p.length - 2];
        Matcher managed = MANAGED_FROM.matcher(annotations);
        Matcher conflict = CONFLICT_WITH.matcher(annotations);
        return new Line(depth, p[0], p[1], version, scope,
                managed.find() ? managed.group(1) : null,
                conflict.find() ? conflict.group(1) : null,
                omitted, annotations.contains("omitted for cycle"), annotations.contains("optional"));
    }

    /** "+- ", "\- ", "|  ", "   " 단위(3글자)로 깊이를 센다. 루트 줄은 0. */
    static int depthOf(String line) {
        int i = 0;
        while (i + 3 <= line.length()) {
            String unit = line.substring(i, i + 3);
            if (unit.equals("|  ") || unit.equals("   ")) {
                i += 3;
            } else if (unit.equals("+- ") || unit.equals("\\- ")) {
                return i / 3 + 1;
            } else {
                break;
            }
        }
        return 0;
    }

    /** 콘솔 출력을 그대로 받은 경우의 "[INFO] " 접두어를 뗀다. */
    private static String stripLogPrefix(String line) {
        return line.startsWith("[INFO] ") ? line.substring(7) : line;
    }
}
