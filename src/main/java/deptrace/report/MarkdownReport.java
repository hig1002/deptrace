package deptrace.report;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import deptrace.analysis.AnalysisResult;
import deptrace.analysis.AnalysisResult.Finding;
import deptrace.analysis.PathTracer;

public final class MarkdownReport {

    private static final Map<String, String> CATEGORY_LABEL = Map.of(
            "REMOVE_DIRECT_PIN", "직접 선언 제거",
            "UPDATE_DIRECT", "직접 선언 버전 상향",
            "UPGRADE_PLATFORM", "Spring Boot(BOM) 업그레이드",
            "CONSTRAIN_TRANSITIVE", "전이 의존성 하한 지정",
            "NO_FIX", "수정 버전 없음",
            "TEST_ONLY", "테스트 범위");

    private MarkdownReport() {
    }

    public static String render(AnalysisResult r) {
        StringBuilder md = new StringBuilder();
        AnalysisResult.Summary s = r.summary();
        md.append("# DepTrace 분석 결과\n\n");
        md.append("- 생성: ").append(r.generatedAt()).append("\n");
        md.append("- 기준 구성: `").append(r.primaryConfiguration()).append("` (구성요소 ").append(s.primaryComponents()).append("개)\n");
        md.append("- 분석 구성: ").append(r.configurations().stream().map(c -> "`" + c + "`").collect(Collectors.joining(", "))).append("\n\n");

        md.append("## 요약\n\n| 항목 | 값 |\n|---|---|\n");
        md.append("| 취약 구성요소 (전체 구성) | ").append(s.vulnerableComponents()).append(" |\n");
        md.append("| 권고 항목 수 (패키지별 중복 포함) | ").append(s.advisoryEntries()).append(" |\n");
        md.append("| 취약 구성요소 (배포 클래스패스) | ").append(s.vulnerableInPrimary()).append(" |\n");
        md.append("| 고유 취약점 (배포 클래스패스, 중복 제거) | ").append(s.uniqueAdvisoriesPrimary()).append(" |\n");
        md.append("| 심각도 (고유 취약점 기준) | ").append(s.severityPrimary().entrySet().stream()
                .map(e -> e.getKey() + " " + e.getValue()).collect(Collectors.joining(", "))).append(" |\n\n");

        md.append("## 수정 지점별 분류 (배포 클래스패스)\n\n| 수정 지점 | 구성요소 수 |\n|---|---|\n");
        s.remediationPrimary().forEach((k, v) -> md.append("| ").append(CATEGORY_LABEL.getOrDefault(k, k)).append(" | ").append(v).append(" |\n"));
        md.append("\n");

        md.append("## 구성요소별 상세 (배포 클래스패스)\n\n");
        for (Finding f : r.findings()) {
            if (!f.inPrimary()) {
                continue;
            }
            md.append("### ").append(f.coordinate()).append(" — ").append(f.maxSeverity()).append("\n\n");
            md.append("- 권고 ").append(f.advisories().size()).append("건: ")
                    .append(f.advisories().stream().limit(6).map(a -> a.id() + "(" + a.severity() + ")").collect(Collectors.joining(", ")))
                    .append(f.advisories().size() > 6 ? " 외" : "").append("\n");
            md.append("- 버전 결정: ").append(f.decisionExplanation()).append("\n");
            md.append("- 유입: 직접 의존성 ").append(f.introducerCount()).append("개 경로\n");
            for (PathTracer.Introduction i : f.introductions().stream().limit(3).toList()) {
                md.append("  - ").append(path(i.path())).append("\n");
            }
            md.append("- 수정 버전: ").append(f.fixVersion() == null ? "없음" : f.fixVersion())
                    .append(f.publishedFixVersion() != null && !f.publishedFixVersion().equals(f.fixVersion())
                            ? " → 실제 배포된 버전 " + f.publishedFixVersion() : "")
                    .append(f.lineChange() ? " (릴리스 라인 변경 필요)" : "")
                    .append(f.allFixable() ? "" : " (일부 권고는 수정 버전 없음)").append("\n");
            if (!f.alternatives().isEmpty()) {
                md.append("- 다른 좌표의 수정 버전: ").append(String.join(", ", f.alternatives())).append("\n");
            }
            md.append("- 조치: **").append(CATEGORY_LABEL.get(f.remediation())).append("** — ").append(f.remediationAdvice()).append("\n\n");
        }

        List<Finding> testOnly = r.findings().stream().filter(f -> !f.inPrimary()).toList();
        if (!testOnly.isEmpty()) {
            md.append("## 테스트 범위 (배포물 미포함, 보고만)\n\n");
            testOnly.forEach(f -> md.append("- ").append(f.coordinate()).append(" — ").append(f.maxSeverity())
                    .append(", 권고 ").append(f.advisories().size()).append("건, 구성: ").append(String.join(", ", f.configurations())).append("\n"));
        }
        return md.toString();
    }

    static String path(List<String> path) {
        return path.stream().skip(1).map(MarkdownReport::shortName).collect(Collectors.joining(" → "));
    }

    private static String shortName(String id) {
        String[] p = id.split(":");
        return p.length == 3 ? p[1] + ":" + p[2] : id;
    }
}
