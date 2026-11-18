package deptrace.report;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.stream.Collectors;

import deptrace.analysis.AnalysisResult;
import deptrace.analysis.AnalysisResult.Finding;
import deptrace.model.Versions;
import deptrace.osv.Severity;

/**
 * 수정 전후 두 분석 결과를 비교한다. "의도한 것만 바뀌었는가"를 확인하는 것이 목적이다.
 * 구성요소는 모듈(group:artifact) 단위로, 취약점은 (모듈, 대표 ID) 단위로 비교한다.
 */
public final class ResultDiff {

    public record ComponentChange(String module, String before, String after) {
    }

    public record Diff(
            List<ComponentChange> upgraded,
            List<ComponentChange> downgraded,
            List<String> added,
            List<String> removed,
            Set<String> fixedAdvisories,
            Set<String> newAdvisories,
            Set<String> remainingAdvisories,
            Map<String, Integer> severityBefore,
            Map<String, Integer> severityAfter,
            int vulnerableBefore,
            int vulnerableAfter) {
    }

    private ResultDiff() {
    }

    public static Diff compare(AnalysisResult before, AnalysisResult after) {
        Map<String, String> b = versions(before.components());
        Map<String, String> a = versions(after.components());

        List<ComponentChange> upgraded = new ArrayList<>();
        List<ComponentChange> downgraded = new ArrayList<>();
        List<String> added = new ArrayList<>();
        List<String> removed = new ArrayList<>();
        Set<String> modules = new TreeSet<>(b.keySet());
        modules.addAll(a.keySet());
        modules.forEach(module -> {
            String vb = b.get(module);
            String va = a.get(module);
            if (vb == null) {
                added.add(module + ":" + va);
            } else if (va == null) {
                removed.add(module + ":" + vb);
            } else if (!vb.equals(va)) {
                (Versions.compare(va, vb) > 0 ? upgraded : downgraded).add(new ComponentChange(module, vb, va));
            }
        });

        Set<String> advBefore = advisoryKeys(before);
        Set<String> advAfter = advisoryKeys(after);
        Set<String> fixed = new TreeSet<>(advBefore);
        fixed.removeAll(advAfter);
        Set<String> introduced = new TreeSet<>(advAfter);
        introduced.removeAll(advBefore);
        Set<String> remaining = new TreeSet<>(advBefore);
        remaining.retainAll(advAfter);

        return new Diff(upgraded, downgraded, added, removed, fixed, introduced, remaining,
                before.summary().severityPrimary(), after.summary().severityPrimary(),
                before.summary().vulnerableInPrimary(), after.summary().vulnerableInPrimary());
    }

    public static String render(Diff d) {
        StringBuilder md = new StringBuilder("# DepTrace 전후 비교 (배포 클래스패스)\n\n");
        md.append("| 항목 | 수정 전 | 수정 후 |\n|---|---|---|\n");
        md.append("| 취약 구성요소 | ").append(d.vulnerableBefore()).append(" | ").append(d.vulnerableAfter()).append(" |\n");
        md.append("| 고유 취약점 (심각도별) | ").append(fmt(d.severityBefore())).append(" | ").append(fmt(d.severityAfter())).append(" |\n\n");
        md.append("- 해결된 (모듈, 취약점): ").append(d.fixedAdvisories().size()).append("\n");
        md.append("- 새로 생긴 (모듈, 취약점): ").append(d.newAdvisories().size()).append("\n");
        md.append("- 남은 (모듈, 취약점): ").append(d.remainingAdvisories().size()).append("\n\n");
        md.append("## 구성요소 변화\n\n");
        md.append("- 상향 ").append(d.upgraded().size()).append(", 하향 ").append(d.downgraded().size())
                .append(", 추가 ").append(d.added().size()).append(", 제거 ").append(d.removed().size()).append("\n\n");
        d.upgraded().forEach(c -> md.append("- ↑ ").append(c.module()).append(" ").append(c.before()).append(" → ").append(c.after()).append("\n"));
        d.downgraded().forEach(c -> md.append("- ↓ ").append(c.module()).append(" ").append(c.before()).append(" → ").append(c.after()).append("\n"));
        d.added().forEach(c -> md.append("- + ").append(c).append("\n"));
        d.removed().forEach(c -> md.append("- − ").append(c).append("\n"));
        if (!d.newAdvisories().isEmpty()) {
            md.append("\n## 새로 생긴 취약점\n\n");
            d.newAdvisories().forEach(k -> md.append("- ").append(k).append("\n"));
        }
        if (!d.remainingAdvisories().isEmpty()) {
            md.append("\n## 남은 취약점\n\n");
            d.remainingAdvisories().forEach(k -> md.append("- ").append(k).append("\n"));
        }
        return md.toString();
    }

    private static Map<String, String> versions(List<String> coordinates) {
        Map<String, String> m = new LinkedHashMap<>();
        for (String c : coordinates) {
            int i = c.lastIndexOf(':');
            m.put(c.substring(0, i), c.substring(i + 1));
        }
        return m;
    }

    private static Set<String> advisoryKeys(AnalysisResult r) {
        return r.findings().stream().filter(Finding::inPrimary)
                .flatMap(f -> f.advisories().stream().map(a -> f.module() + " " + a.canonicalId()))
                .collect(Collectors.toCollection(TreeSet::new));
    }

    private static String fmt(Map<String, Integer> m) {
        if (m.isEmpty()) {
            return "0";
        }
        Map<String, Integer> ordered = new TreeMap<>(Severity.NAME_DESCENDING);
        ordered.putAll(m);
        return ordered.entrySet().stream().map(e -> e.getKey() + " " + e.getValue()).collect(Collectors.joining(", "));
    }
}
