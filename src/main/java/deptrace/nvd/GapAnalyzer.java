package deptrace.nvd;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;

import deptrace.analysis.AnalysisResult;
import deptrace.analysis.AnalysisResult.Advisory;
import deptrace.analysis.AnalysisResult.Finding;
import deptrace.graph.ResolvedGraph;
import deptrace.model.Coordinate;
import deptrace.model.Versions;
import deptrace.nvd.GhsaLookup.Review;
import deptrace.nvd.NvdCve.CpeMatch;
import deptrace.osv.Severity;
import deptrace.policy.PolicyGate.PolicyException;
import deptrace.repository.PublishedVersions;

/**
 * OSV가 아직 패키지에 연결하지 못한 권고를 NVD에서 찾는다 (OSV 결과를 대체하지 않고 공백만 보완).
 *
 * <ol>
 *   <li>배포 클래스패스 구성요소를 대응표로 NVD 제품에 묶는다. 표에 없는 모듈은 보지 않는다(추측 금지).</li>
 *   <li>제품의 CVE 중 현재 버전이 CPE 범위에 드는 것을 고른다.</li>
 *   <li>OSV가 이미 보고한 CVE는 뺀다.</li>
 *   <li>GitHub이 검토해 Maven 패키지에 연결한 CVE도 뺀다. 검토 결과가 "우리 모듈·버전이 아니다"라고 말하고 있기 때문이다.</li>
 *   <li>남은 것(미검토·GHSA 없음·조회 실패)을 제품당 한 번씩 보고한다. jar마다 세지 않는다.</li>
 * </ol>
 */
public final class GapAnalyzer {

    /**
     * @param modules   이 제품에 속하는 배포 구성요소
     * @param nvdRange  매칭된 NVD 범위 표기
     * @param nextSafe  이 CVE의 어떤 범위에도 들지 않는 다음 버전 중 Maven Central에 배포된 가장 낮은 것 (없으면 null)
     */
    public record Gap(String product, String version, List<String> modules, String cve, String severity, String summary,
                      String nvdRange, String ghsaId, String ghsaReview, String nextSafe, String verdict, String note) {
    }

    /** reviewedOtherModule: 검토된 권고가 다른 모듈(또는 다른 버전)을 지목해 제외한 CVE. */
    public record Result(List<Gap> gaps, int nvdMatched, List<String> coveredByOsv, List<String> reviewedElsewhere,
                         Map<String, Integer> productsChecked) {
    }

    private final ProductMap map;
    private final NvdClient.Source nvd;
    private final GhsaLookup.Source ghsa;
    private final PublishedVersions published;

    public GapAnalyzer(ProductMap map, NvdClient.Source nvd, GhsaLookup.Source ghsa, PublishedVersions published) {
        this.map = map;
        this.nvd = nvd;
        this.ghsa = ghsa;
        this.published = published;
    }

    public Result analyze(ResolvedGraph graph, AnalysisResult osv) {
        // 제품 → (버전 → 모듈들). 같은 제품 안에서도 모듈 버전이 다를 수 있어 버전별로 본다
        Map<ProductMap.Product, Map<String, List<Coordinate>>> byProduct = new LinkedHashMap<>();
        for (ResolvedGraph.Node n : graph.components()) {
            map.productOf(n.coordinate()).ifPresent(p -> byProduct.computeIfAbsent(p, k -> new TreeMap<>(Versions.MAVEN_ORDER))
                    .computeIfAbsent(n.coordinate().version(), k -> new ArrayList<>()).add(n.coordinate()));
        }
        // AND 조건 확인용: 클래스패스에 있는 제품들의 버전 (대응표의 모든 CPE 별칭에 같은 버전을 넣는다)
        Map<String, Set<String>> context = new LinkedHashMap<>();
        byProduct.forEach((p, versions) -> p.cpes().forEach(cpe -> context.computeIfAbsent(cpe, k -> new LinkedHashSet<>())
                .addAll(versions.keySet())));
        Set<String> osvCves = osvCves(osv);
        Set<String> classpathModules = new LinkedHashSet<>();
        graph.components().forEach(n -> classpathModules.add(n.coordinate().module()));

        List<Gap> gaps = new ArrayList<>();
        Set<String> covered = new LinkedHashSet<>();
        Set<String> elsewhere = new LinkedHashSet<>();
        Map<String, Integer> checked = new LinkedHashMap<>();
        int matched = 0;
        for (var entry : byProduct.entrySet()) {
            ProductMap.Product product = entry.getKey();
            Map<String, NvdCve> cves = new LinkedHashMap<>();
            for (String cpe : product.cpes()) {
                nvd.cves(cpe).forEach(c -> cves.putIfAbsent(c.id(), c));
            }
            checked.put(product.name(), cves.size());
            for (var versionEntry : entry.getValue().entrySet()) {
                String version = versionEntry.getKey();
                List<Coordinate> modules = versionEntry.getValue();
                for (NvdCve cve : cves.values()) {
                    Optional<CpeMatch> hit = product.cpes().stream()
                            .map(cpe -> CpeMatcher.match(cve, cpe, version, context)).flatMap(Optional::stream).findFirst();
                    if (hit.isEmpty()) {
                        continue;
                    }
                    matched++;
                    if (osvCves.contains(cve.id())) {
                        covered.add(cve.id());
                        continue;
                    }
                    GhsaLookup.Status status = ghsa.status(cve.id());
                    if (status.review() == Review.REVIEWED && !status.mavenPackages().isEmpty()) {
                        elsewhere.add(cve.id() + " (" + status.ghsaId() + ": " + String.join(", ", status.mavenPackages()) + ")");
                        continue;
                    }
                    gaps.add(new Gap(product.name(), version, modules.stream().map(Coordinate::toString).toList(), cve.id(),
                            cve.severity().name(), cve.summary(), describe(hit.get()), status.ghsaId(), status.review().name(),
                            nextSafe(modules.get(0), version, cve, product, context), "GAP", reviewNote(status)));
                }
            }
        }
        gaps.sort(Comparator.comparing((Gap g) -> Severity.parse(g.severity())).reversed()
                .thenComparing(Gap::product).thenComparing(Gap::cve));
        return new Result(gaps, matched, List.copyOf(covered), List.copyOf(elsewhere), checked);
    }

    /** OSV 결과에서 CVE 별칭을 모은다(배포 클래스패스). */
    private static Set<String> osvCves(AnalysisResult osv) {
        Set<String> out = new LinkedHashSet<>();
        if (osv == null) {
            return out;
        }
        for (Finding f : osv.findings()) {
            if (!f.inPrimary()) {
                continue;
            }
            for (Advisory a : f.advisories()) {
                out.add(a.id());
                out.add(a.canonicalId());
                out.addAll(a.aliases());
            }
        }
        return out;
    }

    /**
     * 현재보다 높고, 이 CVE의 어떤 범위에도 들지 않으며, Maven Central에 실제로 배포된 가장 낮은 정식 버전.
     * NVD의 수정 버전(versionEndExcluding)이 상용 지원판에만 있는 경우가 있어(Spring 6.2.20) 배포 여부까지 확인한다.
     */
    private String nextSafe(Coordinate module, String current, NvdCve cve, ProductMap.Product product,
                            Map<String, Set<String>> context) {
        String flavor = PublishedVersions.flavor(current);
        return published.versions(module.module()).flatMap(list -> list.stream()
                .filter(v -> !PublishedVersions.PRE_RELEASE.matcher(v).matches())
                .filter(v -> PublishedVersions.flavor(v).equals(flavor))
                .filter(v -> Versions.compare(v, current) > 0)
                .filter(v -> product.cpes().stream().noneMatch(cpe -> CpeMatcher.match(cve, cpe, v, context).isPresent()))
                .min(Versions.MAVEN_ORDER)).orElse(null);
    }

    private static String describe(CpeMatch m) {
        String[] f = CpeMatcher.split(m.criteria());
        StringBuilder s = new StringBuilder(f[3] + ":" + f[4]);
        if (!f[5].equals("*")) {
            s.append(" = ").append(f[5]);
        }
        if (m.versionStartIncluding() != null) s.append(" ≥ ").append(m.versionStartIncluding());
        if (m.versionStartExcluding() != null) s.append(" > ").append(m.versionStartExcluding());
        if (m.versionEndIncluding() != null) s.append(" ≤ ").append(m.versionEndIncluding());
        if (m.versionEndExcluding() != null) s.append(" < ").append(m.versionEndExcluding());
        return s.toString();
    }

    private static String reviewNote(GhsaLookup.Status s) {
        return switch (s.review()) {
            case UNREVIEWED -> "GitHub 권고 " + s.ghsaId() + "가 미검토 상태라 OSV에 Maven 매핑이 없음";
            case NONE -> "GitHub 권고 없음 (NVD에만 있음)";
            case REVIEWED -> "GitHub이 검토했지만 Maven 패키지 연결이 없음";
            case UNKNOWN -> "GitHub 권고 조회 실패: 미반영으로 간주";
        };
    }

    // ---- 게이트 ----

    public record GateResult(List<String> violations, List<String> accepted, boolean passed) {
    }

    /** 취약점 예외와 같은 파일·규칙을 쓴다. package를 적었다면 그 제품의 모듈 중 하나와 맞아야 한다. */
    public static GateResult gate(Result r, Severity threshold, List<PolicyException> exceptions, LocalDate today) {
        List<String> violations = new ArrayList<>();
        List<String> accepted = new ArrayList<>();
        for (Gap g : r.gaps()) {
            if (!Severity.parse(g.severity()).atLeast(threshold)) {
                continue;
            }
            Optional<PolicyException> ex = exceptions.stream()
                    .filter(e -> g.cve().equals(e.id()) || (g.ghsaId() != null && g.ghsaId().equals(e.id())))
                    .filter(e -> e.packageName() == null || e.packageName().isBlank()
                            || g.modules().stream().anyMatch(m -> m.startsWith(e.packageName() + ":")))
                    .findFirst();
            String label = g.product() + " " + g.version() + " " + g.cve() + " (" + g.severity() + ")";
            if (ex.isPresent() && deptrace.policy.PolicyGate.isActive(ex.get(), today)) {
                accepted.add(label + " — " + ex.get().reason() + " (만료 " + ex.get().expires() + ")");
            } else {
                violations.add(label + (ex.isPresent() ? " — 예외 만료 " + ex.get().expires() : ""));
            }
        }
        return new GateResult(violations, accepted, violations.isEmpty());
    }

    public static String render(Result r, GateResult gate, Severity threshold) {
        StringBuilder md = new StringBuilder("## DepTrace NVD 보완 점검: ")
                .append(gate == null ? "보고만" : gate.passed() ? "통과" : "실패")
                .append(gate == null ? "" : " (기준: " + threshold + " 이상)").append("\n\n")
                .append("OSV가 아직 Maven 패키지에 연결하지 못한 권고를 NVD 제품 단위(CPE)로 찾았습니다. 제품당 한 번씩 셉니다.\n\n");
        md.append("- 점검한 제품: ").append(r.productsChecked()).append("\n")
                .append("- NVD 범위에 든 CVE: ").append(r.nvdMatched())
                .append(" → OSV가 이미 보고 ").append(r.coveredByOsv().size())
                .append(", GitHub 검토 결과 다른 모듈·버전 ").append(r.reviewedElsewhere().size())
                .append(", **OSV 미반영 ").append(r.gaps().size()).append("**\n\n");
        if (gate != null && !gate.violations().isEmpty()) {
            md.append("### 게이트 위반\n\n");
            gate.violations().forEach(v -> md.append("- ").append(v).append("\n"));
            md.append("\n");
        }
        if (gate != null && !gate.accepted().isEmpty()) {
            md.append("### 예외로 인정\n\n");
            gate.accepted().forEach(v -> md.append("- ").append(v).append("\n"));
            md.append("\n");
        }
        if (!r.gaps().isEmpty()) {
            md.append("| 제품 (버전) | CVE | 심각도 | NVD 범위 | 범위 밖 다음 배포 버전 | GitHub 권고 |\n|---|---|---|---|---|---|\n");
            for (Gap g : r.gaps()) {
                md.append("| ").append(g.product()).append(" (").append(g.version()).append(", 모듈 ").append(g.modules().size())
                        .append("개) | ").append(g.cve()).append(" | ").append(g.severity()).append(" | ").append(g.nvdRange())
                        .append(" | ").append(g.nextSafe() == null ? "없음" : g.nextSafe())
                        .append(" | ").append(g.ghsaId() == null ? "-" : g.ghsaId() + " (" + g.ghsaReview() + ")").append(" |\n");
            }
        }
        return md.toString();
    }
}
