package deptrace.cli;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.LocalDate;
import java.util.List;
import java.util.concurrent.Callable;

import deptrace.analysis.AnalysisResult;
import deptrace.analysis.Analyzer;
import deptrace.analysis.PathTracer;
import deptrace.analysis.VersionDecision;
import deptrace.analysis.VersionDecisionClassifier;
import deptrace.graph.GraphLoader;
import deptrace.graph.ResolvedGraph;
import deptrace.osv.OsvClient;
import deptrace.osv.Severity;
import deptrace.policy.PolicyGate;
import deptrace.report.Json;
import deptrace.report.MarkdownReport;
import deptrace.report.ResultDiff;
import deptrace.repository.MavenCentralVersions;
import deptrace.repository.PublishedVersions;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

@Command(name = "deptrace", mixinStandardHelpOptions = true, version = "deptrace 0.1.0",
        description = "Gradle 의존성 해석 결과와 OSV 취약점 정보를 결합해 유입 경로·버전 결정 원인·수정 지점을 알려준다.",
        subcommands = {Main.MavenExport.class, Main.Explain.class, Main.Analyze.class, Main.NvdGaps.class, Main.Licenses.class,
                Main.Sbom.class, Main.Diff.class})
public final class Main {

    public static void main(String[] args) {
        CommandLine cli = new CommandLine(new Main());
        // 입력 오류는 스택 트레이스 대신 메시지만 보여주고 종료 코드 2를 반환한다
        cli.setExecutionExceptionHandler((ex, commandLine, parseResult) -> {
            commandLine.getErr().println("오류: " + ex.getMessage());
            return 2;
        });
        System.exit(cli.execute(args));
    }

    @Command(name = "maven-export", description = "Maven 프로젝트의 해석 결과(dependency:tree -Dverbose)를 DepTrace 그래프로 내보낸다.")
    static final class MavenExport implements Callable<Integer> {

        /** 버전 고정: verbose 트리 형식이 플러그인 버전마다 다를 수 있다. */
        static final String TREE_GOAL = "org.apache.maven.plugins:maven-dependency-plugin:3.9.0:tree";

        @Option(names = "--project", defaultValue = ".", description = "pom.xml이 있는 디렉터리")
        Path project;

        @Option(names = "--mvn", description = "Maven 실행 파일. 기본값: 프로젝트의 mvnw, 없으면 PATH의 mvn")
        String mvn;

        @Option(names = "--tree", description = "이미 만든 트리 파일 (mvn dependency:tree -Dverbose -DoutputFile=...). 주면 Maven을 실행하지 않는다")
        Path tree;

        @Option(names = "--out", description = "출력 디렉터리. 기본값: <project>/target/deptrace")
        Path out;

        @Override
        public Integer call() throws Exception {
            Path dir = project.toAbsolutePath().normalize();
            Path pom = dir.resolve("pom.xml");
            String treeText;
            if (tree != null) {
                treeText = Files.readString(tree);
            } else {
                Path tmp = Files.createTempFile("deptrace-tree", ".txt");
                String exe = mvn != null ? mvn : Files.isExecutable(dir.resolve("mvnw")) ? dir.resolve("mvnw").toString() : "mvn";
                Process p = new ProcessBuilder(exe, "-q", "-B", TREE_GOAL, "-Dverbose", "-DoutputFile=" + tmp.toAbsolutePath())
                        .directory(dir.toFile()).redirectErrorStream(true).start();
                String log = new String(p.getInputStream().readAllBytes());
                if (p.waitFor() != 0) {
                    throw new IllegalStateException("Maven 실행 실패 (" + exe + "):\n" + log);
                }
                treeText = Files.readString(tmp);
                Files.deleteIfExists(tmp);
            }
            var declared = Files.exists(pom) ? deptrace.maven.PomDeclarations.parse(Files.readString(pom))
                    : List.<deptrace.maven.MavenTreeParser.Declared>of();
            Path target = out != null ? out : dir.resolve("target").resolve("deptrace");
            Files.createDirectories(target);
            for (var export : deptrace.maven.MavenTreeParser.parse(treeText, declared, null)) {
                Path file = target.resolve(export.configuration().replace(':', '-') + ".json");
                Json.write(file, export);
                long components = export.nodes().keySet().stream().filter(id -> !id.startsWith("root project")).count();
                System.out.printf("%s: 구성요소 %d개 → %s%n", export.configuration(), components, file);
            }
            return 0;
        }
    }

    @Command(name = "explain", description = "구성요소 하나의 버전 결정 원인과 유입 경로를 보여준다 (오프라인).")
    static final class Explain implements Callable<Integer> {

        @Option(names = "--graphs", required = true, description = "init script 출력 디렉터리 (build/deptrace)")
        Path graphs;

        @Option(names = "--configuration", description = "기본값: productionRuntimeClasspath")
        String configuration;

        @Parameters(description = "group:artifact")
        String module;

        @Override
        public Integer call() {
            List<ResolvedGraph> all = new GraphLoader().loadDirectory(graphs);
            ResolvedGraph graph = configuration == null ? GraphLoader.primary(all) : all.stream()
                    .filter(g -> g.configuration().equals(configuration)).findFirst()
                    .orElseThrow(() -> new IllegalArgumentException("구성이 없습니다: " + configuration));
            ResolvedGraph.Node node = graph.findByModule(module)
                    .orElseThrow(() -> new IllegalArgumentException(graph.configuration() + "에 " + module + "이(가) 없습니다"));

            VersionDecision d = VersionDecisionClassifier.classify(graph, node);
            List<PathTracer.Introduction> intro = PathTracer.introductions(graph, node.id());
            System.out.println(node.id() + "  [" + graph.configuration() + "]");
            System.out.println("  선택 사유(" + (graph.data().isMaven() ? "Maven" : "Gradle") + "): " + String.join(", ", node.causes()));
            System.out.println("  요청 버전: " + (d.requestedVersions().isEmpty() ? "-" : String.join(", ", d.requestedVersions()))
                    + "  직접 선언: " + (d.declared() == null ? "-" : d.declared())
                    + "  BOM 관리: " + (d.managed() == null ? "-" : d.managed()));
            System.out.println("  분류: " + d.kind() + " — " + d.explanation());
            System.out.println("  유입 (직접 의존성 " + intro.size() + "개):");
            intro.forEach(i -> System.out.println("    " + String.join(" → ", i.path().subList(1, i.path().size()))));
            all.stream().filter(g -> g != graph).forEach(g -> g.findByModule(module)
                    .ifPresent(n -> System.out.println("  다른 구성: " + g.configuration() + " → " + n.coordinate().version())));
            return 0;
        }
    }

    @Command(name = "analyze", description = "전체 구성요소를 OSV와 대조해 리포트를 만들고, 정책 위반 시 종료 코드 1을 반환한다.")
    static final class Analyze implements Callable<Integer> {

        @Option(names = "--graphs", required = true, description = "init script 출력 디렉터리 (build/deptrace)")
        Path graphs;

        @Option(names = "--out", defaultValue = "build/deptrace-report", description = "결과 디렉터리 (analysis.json, report.md)")
        Path out;

        @Option(names = "--cache", defaultValue = ".deptrace-cache", description = "OSV 상세 응답·Maven 메타데이터 캐시")
        Path cache;

        @Option(names = "--offline-versions", description = "수정 버전의 실제 배포 여부(Maven Central)를 확인하지 않는다")
        boolean offlineVersions;

        @Option(names = "--fail-on", defaultValue = "NONE", description = "게이트 기준 심각도: NONE, LOW, MODERATE, HIGH, CRITICAL")
        String failOn;

        @Option(names = "--exceptions", description = "예외 파일 (YAML: exceptions: [{id, package, reason, expires}])")
        Path exceptions;

        @Option(names = "--summary", description = "Markdown 요약을 덧붙일 파일 (예: $GITHUB_STEP_SUMMARY)")
        Path summary;

        @Override
        public Integer call() throws Exception {
            OsvClient osv = new OsvClient(cache.resolve("osv"));
            PublishedVersions published = offlineVersions ? PublishedVersions.NONE : new MavenCentralVersions(cache.resolve("maven"));
            AnalysisResult result = new Analyzer(osv, published).analyze(new GraphLoader().loadDirectory(graphs));
            Json.write(out.resolve("analysis.json"), result);
            String report = MarkdownReport.render(result);
            Files.createDirectories(out);
            Files.writeString(out.resolve("report.md"), report);

            AnalysisResult.Summary s = result.summary();
            System.out.printf("배포 클래스패스 구성요소 %d개 중 취약 %d개, 고유 취약점 %d건 %s%n",
                    s.primaryComponents(), s.vulnerableInPrimary(), s.uniqueAdvisoriesPrimary(), s.severityPrimary());
            System.out.println("수정 지점별: " + s.remediationPrimary());
            System.out.println(osv.stats());
            System.out.println("리포트: " + out.resolve("report.md"));

            String gateMarkdown = "";
            int exit = 0;
            if (!failOn.equalsIgnoreCase("NONE")) {
                Severity threshold = Severity.parse(failOn);
                PolicyGate.Result gate = PolicyGate.evaluate(result, threshold, PolicyGate.loadExceptions(exceptions), LocalDate.now());
                gateMarkdown = PolicyGate.render(gate, threshold);
                Files.writeString(out.resolve("gate.md"), gateMarkdown);
                System.out.println("게이트: " + (gate.passed() ? "통과" : "실패 — 위반 " + gate.violations().size() + "건")
                        + (gate.accepted().isEmpty() ? "" : ", 예외 인정 " + gate.accepted().size() + "건"));
                exit = gate.passed() ? 0 : 1;
            }
            if (summary != null) {
                Files.writeString(summary, gateMarkdown + "\n" + report, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            }
            return exit;
        }
    }

    @Command(name = "nvd-gaps", description = "OSV가 아직 Maven 패키지에 연결하지 못한 권고(GitHub 미검토 등)를 NVD 제품 단위로 찾는다.")
    static final class NvdGaps implements Callable<Integer> {

        @Option(names = "--graphs", required = true, description = "init script 출력 디렉터리 (build/deptrace)")
        Path graphs;

        @Option(names = "--analysis", required = true, description = "analyze가 만든 analysis.json (OSV가 이미 보고한 CVE를 빼는 데 쓴다)")
        Path analysis;

        @Option(names = "--out", defaultValue = "build/deptrace-report", description = "결과 디렉터리 (nvd-gaps.json, nvd-gaps.md)")
        Path out;

        @Option(names = "--cache", defaultValue = ".deptrace-cache", description = "NVD·GitHub·Maven 응답 캐시")
        Path cache;

        @Option(names = "--products", description = "NVD 제품 대응표 (YAML). 기본값은 내장 표")
        Path products;

        @Option(names = "--fail-on", defaultValue = "NONE", description = "게이트 기준 심각도: NONE, LOW, MODERATE, HIGH, CRITICAL")
        String failOn;

        @Option(names = "--exceptions", description = "예외 파일 (취약점 예외와 같은 형식, id에 CVE 또는 GHSA)")
        Path exceptions;

        @Option(names = "--summary", description = "Markdown 요약을 덧붙일 파일 (예: $GITHUB_STEP_SUMMARY)")
        Path summary;

        @Override
        public Integer call() throws Exception {
            ResolvedGraph graph = GraphLoader.primary(new GraphLoader().loadDirectory(graphs));
            AnalysisResult osv = Json.read(analysis, AnalysisResult.class);
            var nvd = new deptrace.nvd.NvdClient(cache.resolve("nvd"), System.getenv("NVD_API_KEY"));
            var ghsa = new deptrace.nvd.GhsaLookup(cache.resolve("ghsa"), System.getenv("GITHUB_TOKEN"));
            var map = products == null ? deptrace.nvd.ProductMap.defaults() : deptrace.nvd.ProductMap.load(products);
            var result = new deptrace.nvd.GapAnalyzer(map, nvd.source(), ghsa.source(), new MavenCentralVersions(cache.resolve("maven")))
                    .analyze(graph, osv);

            Severity threshold = failOn.equalsIgnoreCase("NONE") ? null : Severity.parse(failOn);
            var gate = threshold == null ? null
                    : deptrace.nvd.GapAnalyzer.gate(result, threshold, PolicyGate.loadExceptions(exceptions), LocalDate.now());
            String md = deptrace.nvd.GapAnalyzer.render(result, gate, threshold);
            Json.write(out.resolve("nvd-gaps.json"), result);
            Files.writeString(out.resolve("nvd-gaps.md"), md);
            if (summary != null) {
                Files.writeString(summary, md + "\n", StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            }
            System.out.printf("NVD 범위에 든 CVE %d건 → OSV 보고 %d, 검토상 다른 모듈 %d, OSV 미반영 %d%n", result.nvdMatched(),
                    result.coveredByOsv().size(), result.reviewedElsewhere().size(), result.gaps().size());
            System.out.println(nvd.stats());
            System.out.println("리포트: " + out.resolve("nvd-gaps.md"));
            if (gate != null) {
                System.out.println("게이트: " + (gate.passed() ? "통과" : "실패 — 위반 " + gate.violations().size() + "건")
                        + (gate.accepted().isEmpty() ? "" : ", 예외 인정 " + gate.accepted().size() + "건"));
                return gate.passed() ? 0 : 1;
            }
            return 0;
        }
    }

    @Command(name = "licenses", description = "배포 클래스패스 구성요소의 라이선스를 POM에서 판정하고, 정책 위반 시 종료 코드 1을 반환한다.")
    static final class Licenses implements Callable<Integer> {

        @Option(names = "--graphs", required = true, description = "init script 출력 디렉터리 (build/deptrace)")
        Path graphs;

        @Option(names = "--out", defaultValue = "build/deptrace-report", description = "결과 디렉터리 (licenses.json, licenses.md)")
        Path out;

        @Option(names = "--cache", defaultValue = ".deptrace-cache", description = "POM 캐시")
        Path cache;

        @Option(names = "--policy", description = "라이선스 정책 파일 (YAML). 없으면 강한·네트워크 카피레프트 금지, 약한 카피레프트·미확인은 검토")
        Path policy;

        @Option(names = "--summary", description = "Markdown 요약을 덧붙일 파일 (예: $GITHUB_STEP_SUMMARY)")
        Path summary;

        @Override
        public Integer call() throws Exception {
            ResolvedGraph graph = GraphLoader.primary(new GraphLoader().loadDirectory(graphs));
            deptrace.license.PomSource.MavenCentral poms = new deptrace.license.PomSource.MavenCentral(cache.resolve("pom"));
            var licenses = deptrace.license.LicenseReport.resolveAll(graph, new deptrace.license.LicenseResolver(poms));
            var result = deptrace.license.LicensePolicy.load(policy).evaluate(licenses, LocalDate.now());
            var report = deptrace.license.LicenseReport.build(graph, licenses, result);

            Json.write(out.resolve("licenses.json"), report);
            String md = report.toMarkdown();
            Files.writeString(out.resolve("licenses.md"), md);
            if (summary != null) {
                Files.writeString(summary, md + "\n", StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            }

            System.out.printf("%s 구성요소 %d개: %s%n", graph.configuration(), report.components(), report.byCategory());
            System.out.println(poms.stats());
            System.out.println("리포트: " + out.resolve("licenses.md"));
            System.out.println("게이트: " + (report.passed() ? "통과" : "실패 — 금지 "
                    + result.with(deptrace.license.LicensePolicy.Verdict.DENIED).size() + "건")
                    + ", 검토 필요 " + result.with(deptrace.license.LicensePolicy.Verdict.REVIEW).size() + "건");
            return report.passed() ? 0 : 1;
        }
    }

    @Command(name = "sbom", description = "배포 클래스패스를 CycloneDX 1.6 JSON SBOM으로 내보낸다. analyze 결과를 주면 VEX 분석 상태를 붙인다.")
    static final class Sbom implements Callable<Integer> {

        @Option(names = "--graphs", required = true, description = "init script 출력 디렉터리 (build/deptrace)")
        Path graphs;

        @Option(names = "--out", defaultValue = "build/deptrace-report/bom.cdx.json", description = "SBOM 파일 경로")
        Path out;

        @Option(names = "--cache", defaultValue = ".deptrace-cache", description = "POM 캐시")
        Path cache;

        @Option(names = "--analysis", description = "analyze가 만든 analysis.json. 주면 vulnerabilities(VEX)를 포함한다")
        Path analysis;

        @Option(names = "--exceptions", description = "취약점 예외 파일. 유효한 예외는 not_affected로 표시한다")
        Path exceptions;

        @Option(names = "--no-licenses", description = "POM 라이선스 조회를 건너뛴다 (오프라인)")
        boolean noLicenses;

        @Override
        public Integer call() throws Exception {
            ResolvedGraph graph = GraphLoader.primary(new GraphLoader().loadDirectory(graphs));
            List<deptrace.license.LicenseResolver.ComponentLicense> licenses = noLicenses ? List.of()
                    : deptrace.license.LicenseReport.resolveAll(graph,
                            new deptrace.license.LicenseResolver(new deptrace.license.PomSource.MavenCentral(cache.resolve("pom"))));
            AnalysisResult result = analysis == null ? null : Json.read(analysis, AnalysisResult.class);
            var bom = deptrace.sbom.CycloneDxWriter.write(graph, licenses, result, PolicyGate.loadExceptions(exceptions),
                    LocalDate.now(), new CommandLine(new Main()).getCommandSpec().version()[0].replace("deptrace ", ""));

            if (out.toAbsolutePath().getParent() != null) {
                Files.createDirectories(out.toAbsolutePath().getParent());
            }
            Files.writeString(out, deptrace.sbom.CycloneDxWriter.toJson(bom));
            System.out.printf("CycloneDX %s SBOM: 구성요소 %d개, 의존 관계 %d개%s → %s%n",
                    deptrace.sbom.CycloneDxWriter.SPEC_VERSION, bom.get("components").size(), bom.get("dependencies").size(),
                    bom.has("vulnerabilities") ? ", 취약점 " + bom.get("vulnerabilities").size() + "건" : "", out);
            return 0;
        }
    }

    @Command(name = "diff", description = "수정 전후 analysis.json을 비교한다.")
    static final class Diff implements Callable<Integer> {

        @Option(names = "--before", required = true)
        Path before;

        @Option(names = "--after", required = true)
        Path after;

        @Option(names = "--out", description = "Markdown 출력 파일")
        Path out;

        @Override
        public Integer call() throws Exception {
            ResultDiff.Diff d = ResultDiff.compare(Json.read(before, AnalysisResult.class), Json.read(after, AnalysisResult.class));
            String md = ResultDiff.render(d);
            if (out != null) {
                Files.createDirectories(out.toAbsolutePath().getParent());
                Files.writeString(out, md);
            }
            System.out.println(md);
            return 0;
        }
    }
}
