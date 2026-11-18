package deptrace.license;

import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import deptrace.analysis.PathTracer;
import deptrace.graph.ResolvedGraph;
import deptrace.license.LicensePolicy.Decision;
import deptrace.license.LicensePolicy.Verdict;
import deptrace.license.LicenseResolver.ComponentLicense;
import deptrace.model.Coordinate;

/**
 * 배포 클래스패스의 라이선스 판정 결과. 허용이 아닌 항목에는 유입 경로를 붙여
 * "누가 끌고 왔는지, 어디서 빼거나 바꿔야 하는지"까지 보이게 한다.
 */
public record LicenseReport(String generatedAt, String configuration, int components,
                            Map<String, Integer> byCategory, Map<String, Integer> byLicense,
                            List<Entry> entries, List<String> problems, boolean passed) {

    public record Entry(String coordinate, String verdict, String expression, String chosen, String category,
                        String status, String declaredIn, List<String> declared, String note,
                        List<PathTracer.Introduction> introductions) {
    }

    private static final int MAX_INTRODUCTIONS = 3;

    /** POM 조회가 네트워크 대기 위주라 소수의 스레드로 병렬 처리한다. Maven Central에 부담을 주지 않을 정도로 제한. */
    private static final int THREADS = 8;

    public static List<ComponentLicense> resolveAll(ResolvedGraph graph, LicenseResolver resolver) throws Exception {
        List<Coordinate> coordinates = graph.components().stream().map(ResolvedGraph.Node::coordinate).toList();
        ExecutorService pool = Executors.newFixedThreadPool(THREADS);
        try {
            List<Future<ComponentLicense>> futures = new ArrayList<>();
            for (Coordinate c : coordinates) {
                futures.add(pool.submit(() -> resolver.resolve(c)));
            }
            List<ComponentLicense> out = new ArrayList<>();
            for (Future<ComponentLicense> f : futures) {
                out.add(f.get());
            }
            return out;
        } finally {
            pool.shutdown();
        }
    }

    public static LicenseReport build(ResolvedGraph graph, List<ComponentLicense> licenses, LicensePolicy.Result result) {
        Map<String, Integer> byCategory = new TreeMap<>();
        Map<String, Integer> byLicense = new TreeMap<>();
        List<Entry> entries = new ArrayList<>();
        for (Decision d : result.decisions()) {
            ComponentLicense l = d.license();
            byCategory.merge(l.category().name(), 1, Integer::sum);
            byLicense.merge(l.expression(), 1, Integer::sum);
            List<PathTracer.Introduction> intro = d.verdict() == Verdict.ALLOWED ? List.of()
                    : PathTracer.introductions(graph, l.coordinate()).stream().limit(MAX_INTRODUCTIONS).toList();
            entries.add(new Entry(l.coordinate(), d.verdict().name(), l.expression(), d.chosen(), l.category().name(),
                    l.status().name(), l.declaredIn(),
                    l.declared().stream().map(x -> x.name() != null ? x.name() : x.url()).toList(),
                    d.note(), intro));
        }
        entries.sort(Comparator.comparing((Entry e) -> Verdict.valueOf(e.verdict()).ordinal()).reversed()
                .thenComparing(Entry::coordinate));
        return new LicenseReport(OffsetDateTime.now(ZoneId.of("UTC")).truncatedTo(ChronoUnit.SECONDS).toString(),
                graph.configuration(), licenses.size(), byCategory, byLicense, entries, result.problems(), result.passed());
    }

    public String toMarkdown() {
        StringBuilder md = new StringBuilder("## DepTrace 라이선스 게이트: ").append(passed ? "통과" : "실패")
                .append(" (기준: ").append(configuration).append(", 구성요소 ").append(components).append("개)\n\n");
        problems.forEach(p -> md.append("- 설정 오류: ").append(p).append("\n"));

        md.append("| 분류 | 구성요소 수 |\n|---|---|\n");
        for (LicenseCategory c : LicenseCategory.values()) {
            int n = byCategory.getOrDefault(c.name(), 0);
            if (n > 0) {
                md.append("| ").append(c.label()).append(" (").append(c.name()).append(") | ").append(n).append(" |\n");
            }
        }

        section(md, Verdict.DENIED, "금지 (게이트 실패)");
        section(md, Verdict.ACCEPTED, "예외로 인정");
        section(md, Verdict.REVIEW, "검토 필요");

        md.append("\n<details><summary>라이선스별 구성요소 수</summary>\n\n| 라이선스 | 수 |\n|---|---|\n");
        byLicense.entrySet().stream().sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
                .forEach(e -> md.append("| ").append(e.getKey()).append(" | ").append(e.getValue()).append(" |\n"));
        md.append("\n</details>\n");
        return md.toString();
    }

    private void section(StringBuilder md, Verdict verdict, String title) {
        List<Entry> list = entries.stream().filter(e -> e.verdict().equals(verdict.name())).toList();
        if (list.isEmpty()) {
            return;
        }
        md.append("\n### ").append(title).append(" (").append(list.size()).append(")\n\n");
        for (Entry e : list) {
            md.append("- **").append(e.coordinate()).append("** — ").append(e.expression())
                    .append(" [").append(LicenseCategory.valueOf(e.category()).label()).append("]");
            if (e.note() != null && !e.note().isEmpty()) {
                md.append(" · ").append(e.note());
            }
            md.append("\n");
            if (!e.declared().isEmpty()) {
                md.append("  - POM 선언: ").append(String.join(" / ", e.declared()));
                if (e.declaredIn() != null && !e.declaredIn().equals(e.coordinate())) {
                    md.append(" (부모 ").append(e.declaredIn()).append("에서 상속)");
                }
                md.append("\n");
            }
            for (PathTracer.Introduction i : e.introductions()) {
                md.append("  - 유입: ").append(String.join(" → ", i.path().subList(1, i.path().size()))).append("\n");
            }
        }
    }
}
