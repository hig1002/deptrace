package deptrace.analysis;

import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

import deptrace.analysis.AnalysisResult.Advisory;
import deptrace.analysis.AnalysisResult.Finding;
import deptrace.graph.GraphLoader;
import deptrace.graph.ResolvedGraph;
import deptrace.model.Coordinate;
import deptrace.model.Versions;
import deptrace.osv.FixVersionResolver;
import deptrace.osv.OsvVulnerability;
import deptrace.osv.Severity;
import deptrace.osv.VulnerabilitySource;
import deptrace.repository.PublishedVersions;

/**
 * 해석 그래프와 취약점 데이터를 결합한다.
 * 취약점 판정 자체는 OSV에 맡기고, 이 클래스는 "그 결과를 조치 가능한 형태로" 만드는 데 집중한다:
 * 배포 범위 여부, 버전 결정 원인, 유입 경로, 수정 버전, 수정 지점.
 */
public final class Analyzer {

    private static final int MAX_INTRODUCTIONS = 5;

    private final VulnerabilitySource source;
    private final PublishedVersions published;

    public Analyzer(VulnerabilitySource source, PublishedVersions published) {
        this.source = source;
        this.published = published;
    }

    public AnalysisResult analyze(List<ResolvedGraph> graphs) {
        ResolvedGraph primary = GraphLoader.primary(graphs);

        // 좌표별로 어느 구성에 들어 있는지 (같은 모듈이라도 구성마다 다른 버전이 선택될 수 있다)
        Map<Coordinate, List<String>> configurationsOf = new LinkedHashMap<>();
        for (ResolvedGraph g : graphs) {
            for (ResolvedGraph.Node n : g.components()) {
                configurationsOf.computeIfAbsent(n.coordinate(), k -> new ArrayList<>()).add(g.configuration());
            }
        }

        Map<Coordinate, List<OsvVulnerability>> vulnerable = source.vulnerabilities(configurationsOf.keySet());

        List<Finding> findings = new ArrayList<>();
        vulnerable.forEach((coordinate, vulns) -> {
            List<String> configs = configurationsOf.get(coordinate);
            boolean inPrimary = configs.contains(primary.configuration());
            ResolvedGraph graph = inPrimary ? primary : graphs.stream()
                    .filter(g -> configs.contains(g.configuration())).findFirst().orElseThrow();
            ResolvedGraph.Node node = graph.node(coordinate.toString()).orElseThrow();
            findings.add(finding(graph, node, inPrimary, configs, vulns));
        });

        findings.sort(Comparator.comparing(Finding::inPrimary).reversed()
                .thenComparing(f -> Severity.valueOf(f.maxSeverity()), Comparator.reverseOrder())
                .thenComparing(Finding::module));

        return new AnalysisResult(
                OffsetDateTime.now(ZoneId.systemDefault()).truncatedTo(ChronoUnit.SECONDS).toString(),
                primary.project(),
                primary.configuration(),
                graphs.stream().map(ResolvedGraph::configuration).toList(),
                primary.components().stream().map(n -> n.coordinate().toString()).sorted().toList(),
                findings,
                summarize(primary, findings));
    }

    private Finding finding(ResolvedGraph graph, ResolvedGraph.Node node, boolean inPrimary,
                            List<String> configs, List<OsvVulnerability> vulns) {
        Coordinate c = node.coordinate();
        VersionDecision decision = VersionDecisionClassifier.classify(graph, node);
        List<PathTracer.Introduction> introductions = PathTracer.introductions(graph, node.id());

        // 같은 취약점이 GHSA·CVE 등 여러 ID로 들어오면 대표 ID로 묶는다
        Map<String, Advisory> advisories = new LinkedHashMap<>();
        for (OsvVulnerability v : vulns) {
            FixVersionResolver.FixInfo fix = FixVersionResolver.resolve(v, c);
            advisories.merge(v.canonicalId(),
                    new Advisory(v.id(), v.canonicalId(), v.aliases(), v.severity().name(), v.summary(),
                            fix.sameLine(), fix.nextSafe(), fix.alternatives()),
                    (a, b) -> Severity.valueOf(a.severity()).atLeast(Severity.valueOf(b.severity())) ? a : b);
        }
        List<Advisory> list = new ArrayList<>(advisories.values());
        list.sort(Comparator.comparing((Advisory a) -> Severity.valueOf(a.severity())).reversed().thenComparing(Advisory::id));

        // 모든 권고를 해소하려면 권고별 "안전한 다음 버전" 중 가장 높은 버전이 필요하다
        boolean allFixable = list.stream().allMatch(a -> a.nextSafe() != null);
        String fixVersion = list.stream().map(Advisory::nextSafe).filter(Objects::nonNull)
                .max(Versions.MAVEN_ORDER).orElse(null);
        boolean lineChange = list.stream().anyMatch(a -> a.fixedInLine() == null && a.nextSafe() != null);
        List<String> alternatives = list.stream().filter(a -> a.nextSafe() == null)
                .flatMap(a -> a.alternatives().stream()).distinct().toList();
        String maxSeverity = list.stream().map(a -> Severity.valueOf(a.severity()))
                .max(Comparator.naturalOrder()).orElse(Severity.UNKNOWN).name();

        // 권고의 수정 버전이 실제로 배포됐는지 확인하고, 아니면 배포된 가장 낮은 정식 버전으로 바꾼다
        String publishedFix = null;
        String fixNote = "";
        if (fixVersion != null && published.versions(c.module()).isPresent()) {
            publishedFix = published.lowestPublishedAtLeast(c.module(), fixVersion).orElse(null);
            if (publishedFix == null) {
                fixNote = " OSV 수정 버전 " + fixVersion + " 이상은 아직 Maven Central에 배포되지 않았다.";
            } else if (!publishedFix.equals(fixVersion)) {
                fixNote = " OSV 수정 버전 " + fixVersion + "은 Maven Central에 배포되지 않아 " + publishedFix + "을 기준으로 한다.";
            }
        }
        String effectiveFix = publishedFix != null ? publishedFix : fixVersion;

        List<String> introducers = introductions.stream().map(PathTracer.Introduction::introducer).toList();
        Remediation remediation = Remediation.advise(decision, inPrimary, effectiveFix, allFixable, lineChange,
                alternatives, c.module(), introducers.stream().limit(3).toList());

        return new Finding(c.toString(), c.module(), c.version(), inPrimary, configs, maxSeverity, list,
                decision.kind().name(), decision.explanation(), decision.downgraded(),
                introductions.size(), introductions.stream().limit(MAX_INTRODUCTIONS).toList(),
                fixVersion, publishedFix, allFixable, lineChange, alternatives,
                remediation.category().name(), remediation.advice() + fixNote);
    }

    private AnalysisResult.Summary summarize(ResolvedGraph primary, List<Finding> findings) {
        List<Finding> prod = findings.stream().filter(Finding::inPrimary).toList();

        Map<String, Severity> uniquePrimary = new LinkedHashMap<>();
        prod.forEach(f -> f.advisories().forEach(a -> uniquePrimary.merge(a.canonicalId(), Severity.valueOf(a.severity()),
                (x, y) -> x.atLeast(y) ? x : y)));

        Map<String, Integer> severity = new TreeMap<>(Severity.NAME_DESCENDING);
        uniquePrimary.values().forEach(s -> severity.merge(s.name(), 1, Integer::sum));

        Map<String, Integer> remediation = new LinkedHashMap<>();
        for (Remediation.Category category : Remediation.Category.values()) {
            int n = (int) prod.stream().filter(f -> f.remediation().equals(category.name())).count();
            if (n > 0) {
                remediation.put(category.name(), n);
            }
        }

        return new AnalysisResult.Summary(
                primary.components().size(),
                findings.size(),
                prod.size(),
                findings.stream().mapToInt(f -> f.advisories().size()).sum(),
                uniquePrimary.size(),
                severity,
                remediation);
    }
}
