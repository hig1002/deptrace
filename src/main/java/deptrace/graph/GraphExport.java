package deptrace.graph;

import java.util.List;
import java.util.Map;

/**
 * 해석 그래프 JSON의 구조. 구성(configuration) 하나당 파일 하나.
 * Gradle은 init script(deptrace.init.gradle), Maven은 deptrace maven-export가 만든다.
 *
 * @param buildTool "gradle" 또는 "maven". 이전 형식 파일에는 없다(null = gradle)
 */
public record GraphExport(
        String format,
        String project,
        String projectName,
        String projectGroup,
        String projectVersion,
        String configuration,
        String gradleVersion,
        String root,
        List<DeclaredDependency> directDependencies,
        Map<String, String> managedVersions,
        Map<String, NodeData> nodes,
        List<EdgeData> edges,
        String buildTool) {

    public boolean isMaven() {
        return "maven".equals(buildTool);
    }

    /** 빌드 스크립트에 직접 선언된 의존성. version이 null이면 BOM 관리 버전을 따른다. */
    public record DeclaredDependency(String group, String name, String version, String declaredIn) {
    }

    public record NodeData(String module, String version, List<Reason> reasons) {
    }

    /** Gradle ComponentSelectionDescriptor: cause는 REQUESTED, CONFLICT_RESOLUTION, SELECTED_BY_RULE, CONSTRAINT, FORCED 등. */
    public record Reason(String cause, String description) {
    }

    /** requested: 요청 좌표·버전 표기, to: 실제 선택된 구성요소, constraint: BOM/platform 제약 엣지 여부. */
    public record EdgeData(String from, String requested, String to, boolean constraint, boolean unresolved) {
    }
}
