package deptrace.server.api;

import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import jakarta.validation.constraints.Pattern;

import deptrace.osv.Severity;
import deptrace.server.domain.Advisory;
import deptrace.server.domain.AdvisoryRepository;
import deptrace.server.domain.Finding;
import deptrace.server.domain.FindingRepository;
import deptrace.server.domain.Project;
import deptrace.server.domain.ProjectRepository;
import deptrace.server.ingest.SbomIngestService;
import deptrace.server.rescan.RescanLauncher;

@RestController
@RequestMapping("/api")
public class ApiController {

    public record FindingView(long id, String component, String advisory, List<String> aliases, String severity,
                              String summary, String status, String detectedBy, String firstSeenAt, String resolvedAt) {

        static FindingView of(Finding f) {
            Advisory a = f.getAdvisory();
            return new FindingView(f.getId(), f.getComponent().getPurl(), a.getId(), List.copyOf(a.getAliases()),
                    String.valueOf(a.getSeverity()), a.getSummary(), f.getStatus().name(), f.getDetectedBy().name(),
                    String.valueOf(f.getFirstSeenAt()), f.getResolvedAt() == null ? null : f.getResolvedAt().toString());
        }
    }

    public record ProjectView(String key, Map<String, Long> openBySeverity) {
    }

    /** 영향 조회 결과: 프로젝트별로 어떤 구성요소가 걸렸는지. */
    public record Impact(String query, List<String> advisories, Map<String, List<String>> projects) {
    }

    private final SbomIngestService ingest;
    private final RescanLauncher rescan;
    private final ProjectRepository projects;
    private final FindingRepository findings;
    private final AdvisoryRepository advisories;

    public ApiController(SbomIngestService ingest, RescanLauncher rescan, ProjectRepository projects,
                         FindingRepository findings, AdvisoryRepository advisories) {
        this.ingest = ingest;
        this.rescan = rescan;
        this.projects = projects;
        this.findings = findings;
        this.advisories = advisories;
    }

    /** CI가 deptrace sbom으로 만든 CycloneDX를 올린다. */
    @PostMapping(path = "/projects/{key}/sboms", consumes = "application/json")
    public ResponseEntity<SbomIngestService.Result> upload(
            @PathVariable @Pattern(regexp = "[A-Za-z0-9._-]{1,100}") String key, @RequestBody byte[] sbom) {
        return ResponseEntity.status(HttpStatus.CREATED).body(ingest.ingest(key, sbom));
    }

    @GetMapping("/projects")
    @Transactional(readOnly = true)
    public List<ProjectView> projects() {
        return projects.findAll().stream().sorted(Comparator.comparing(Project::getKey)).map(p -> {
            Map<String, Long> bySeverity = new TreeMap<>(Comparator.comparing(Severity::parse).reversed());
            findings.findForProject(p, Finding.Status.OPEN)
                    .forEach(f -> bySeverity.merge(String.valueOf(f.getAdvisory().getSeverity()), 1L, Long::sum));
            return new ProjectView(p.getKey(), bySeverity);
        }).toList();
    }

    @GetMapping("/projects/{key}/findings")
    @Transactional(readOnly = true)
    public List<FindingView> findings(@PathVariable String key, @RequestParam(required = false) Finding.Status status) {
        Project p = projects.findByKey(key).orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "프로젝트 없음: " + key));
        return findings.findForProject(p, status).stream().map(FindingView::of).toList();
    }

    /**
     * "이 권고(GHSA 또는 CVE)에 영향받는 프로젝트는?" 대형 취약점이 공개됐을 때 첫 질문이다.
     * 별칭으로도 찾으므로 CVE 번호만 알아도 된다.
     */
    @GetMapping("/advisories/{id}/impact")
    @Transactional(readOnly = true)
    public Impact advisoryImpact(@PathVariable String id) {
        List<String> ids = advisories.findByIdOrAlias(id).stream().map(Advisory::getId).toList();
        Map<String, List<String>> byProject = new TreeMap<>();
        if (!ids.isEmpty()) {
            findings.findOpenByAdvisoryIds(ids).forEach(f -> byProject
                    .computeIfAbsent(f.getProject().getKey(), k -> new java.util.ArrayList<>()).add(f.getComponent().getPurl()));
        }
        return new Impact(id, ids, byProject);
    }

    /** "group:artifact를 쓰는 프로젝트와 버전은?" 권고가 아직 없는 문제(예: 라이선스 변경, 공급망 사고)에도 쓴다. */
    @GetMapping("/components/usage")
    @Transactional(readOnly = true)
    public Map<String, List<String>> componentUsage(@RequestParam String module) {
        Map<String, List<String>> out = new LinkedHashMap<>();
        for (Project p : projects.findAll()) {
            if (p.getCurrentSnapshot() == null) {
                continue;
            }
            List<String> versions = p.getCurrentSnapshot().getComponents().stream()
                    .filter(c -> c.module().equals(module)).map(c -> c.getVersion()).sorted().toList();
            if (!versions.isEmpty()) {
                out.put(p.getKey(), versions);
            }
        }
        return out;
    }

    @PostMapping("/rescan")
    public RescanLauncher.Summary rescan() {
        return rescan.run("api");
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, String>> badRequest(IllegalArgumentException e) {
        return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
    }
}
