package deptrace.analysis;

import java.util.List;
import java.util.Map;

/**
 * analyze 결과. JSON으로 저장해 diff와 정책 게이트의 입력으로 쓴다.
 *
 * @param components 기준 구성(배포 클래스패스)의 구성요소 좌표 전체
 */
public record AnalysisResult(
        String generatedAt,
        String project,
        String primaryConfiguration,
        List<String> configurations,
        List<String> components,
        List<Finding> findings,
        Summary summary) {

    public record Finding(
            String coordinate,
            String module,
            String version,
            boolean inPrimary,
            List<String> configurations,
            String maxSeverity,
            List<Advisory> advisories,
            String decision,
            String decisionExplanation,
            boolean downgraded,
            int introducerCount,
            List<PathTracer.Introduction> introductions,
            String fixVersion,
            String publishedFixVersion,
            boolean allFixable,
            boolean lineChange,
            List<String> alternatives,
            String remediation,
            String remediationAdvice) {
    }

    /**
     * id: OSV ID(주로 GHSA), canonicalId: 도구 간 비교용 대표 ID(CVE 우선),
     * fixedInLine: 현재 릴리스 라인의 수정 버전, nextSafe: 영향 범위를 벗어나는 가장 낮은 버전,
     * alternatives: 같은 권고가 다른 좌표에 둔 수정 버전(좌표 이동·포크 단서).
     */
    public record Advisory(String id, String canonicalId, List<String> aliases, String severity, String summary,
                           String fixedInLine, String nextSafe, List<String> alternatives) {
    }

    /**
     * @param uniqueAdvisoriesPrimary 배포 클래스패스 기준, 같은 취약점을 패키지마다 세지 않은 수
     */
    public record Summary(
            int primaryComponents,
            int vulnerableComponents,
            int vulnerableInPrimary,
            int advisoryEntries,
            int uniqueAdvisoriesPrimary,
            Map<String, Integer> severityPrimary,
            Map<String, Integer> remediationPrimary) {
    }
}
