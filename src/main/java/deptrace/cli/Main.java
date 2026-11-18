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
        subcommands = {Main.Explain.class, Main.Analyze.class, Main.Licenses.class, Main.Diff.class})
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
            System.out.println("  선택 사유(Gradle): " + String.join(", ", node.causes()));
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
