package deptrace.server.api;

import java.time.Clock;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import deptrace.server.config.DeptraceProperties;
import deptrace.server.domain.Finding;
import deptrace.server.domain.FindingRepository;
import deptrace.server.domain.Project;
import deptrace.server.domain.ProjectRepository;
import deptrace.server.domain.RiskAcceptance;
import deptrace.server.domain.RiskAcceptanceRepository;
import deptrace.server.notify.Notifier;
import deptrace.server.scan.FindingReconciler;

/**
 * 예외(위험 수용) 관리. CLI의 deptrace-exceptions.yml과 같은 규칙을 서버 쪽 생명주기로 옮겼다.
 * 만들거나 철회하면 그 프로젝트의 발견 상태를 바로 맞춘다. 만료는 매일 재검사가 처리한다.
 */
@RestController
@RequestMapping("/api")
public class ExceptionController {

    /**
     * @param advisory GHSA ID 또는 CVE
     * @param module   group:artifact (선택). 비우면 이 권고가 걸린 모든 구성요소
     * @param reason   왜 지금 영향이 없는지와 확인 방법. 다음 검토자가 같은 확인을 재현할 수 있어야 한다
     */
    public record Request(@NotBlank String advisory, String module,
                          @NotBlank @Size(min = 10, message = "사유는 확인 방법을 포함해 10자 이상이어야 합니다") String reason,
                          @NotNull LocalDate expiresOn, String requestedBy) {
    }

    public record View(long id, String project, String advisory, String module, String reason, String expiresOn,
                       String requestedBy, String state, long coveredFindings, String createdAt, String revokedAt) {
    }

    public record Created(View exception, int accepted) {
    }

    private final ProjectRepository projects;
    private final RiskAcceptanceRepository acceptances;
    private final FindingRepository findings;
    private final FindingReconciler reconciler;
    private final Notifier notifier;
    private final TransactionTemplate tx;
    private final DeptraceProperties props;
    private final Clock clock;

    public ExceptionController(ProjectRepository projects, RiskAcceptanceRepository acceptances, FindingRepository findings,
                               FindingReconciler reconciler, Notifier notifier, TransactionTemplate tx,
                               DeptraceProperties props, Clock clock) {
        this.projects = projects;
        this.acceptances = acceptances;
        this.findings = findings;
        this.reconciler = reconciler;
        this.notifier = notifier;
        this.tx = tx;
        this.props = props;
        this.clock = clock;
    }

    @PostMapping("/projects/{key}/exceptions")
    public ResponseEntity<Created> create(@PathVariable String key, @Valid @RequestBody Request req) {
        LocalDate today = today();
        LocalDate latest = today.plusDays(props.exceptions().maxDuration().toDays());
        if (req.expiresOn().isBefore(today)) {
            throw new IllegalArgumentException("만료일이 이미 지났습니다: " + req.expiresOn());
        }
        if (req.expiresOn().isAfter(latest)) {
            throw new IllegalArgumentException("만료일은 최대 " + props.exceptions().maxDuration().toDays() + "일 뒤(" + latest
                    + ")까지입니다. 길게 잡으면 다시 검토할 시점이 사라집니다");
        }
        Project project = project(key);
        RiskAcceptance saved = acceptances.save(new RiskAcceptance(project, req.advisory().strip(),
                req.module() == null || req.module().isBlank() ? null : req.module().strip(),
                req.reason().strip(), req.expiresOn(), req.requestedBy(), clock.instant()));

        FindingReconciler.Result r = reconciler.reconcile(project, Finding.DetectedBy.RESCAN);
        notifier.send(r.alerts());
        return ResponseEntity.status(HttpStatus.CREATED).body(new Created(view(saved.getId()), r.accepted()));
    }

    @GetMapping("/projects/{key}/exceptions")
    @Transactional(readOnly = true)
    public List<View> list(@PathVariable String key) {
        return acceptances.findByProjectOrderByCreatedAtDesc(project(key)).stream().map(this::toView).toList();
    }

    /** 철회. 기록은 남기고(감사 목적) 덮던 발견은 바로 다시 연다. */
    @DeleteMapping("/projects/{key}/exceptions/{id}")
    public View revoke(@PathVariable String key, @PathVariable long id) {
        Project project = project(key);
        tx.executeWithoutResult(s -> {
            RiskAcceptance r = acceptances.findById(id)
                    .filter(a -> a.getProject().getId().equals(project.getId()))
                    .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "예외 없음: " + id));
            if (r.getRevokedAt() == null) {
                r.revoke(clock.instant());
            }
        });
        notifier.send(reconciler.reconcile(project, Finding.DetectedBy.RESCAN).alerts());
        return view(id);
    }

    /** 곧 만료되는 예외 (모든 프로젝트). 만료돼 알림이 오기 전에 다시 검토할 수 있게 한다. */
    @GetMapping("/exceptions/expiring")
    @Transactional(readOnly = true)
    public List<View> expiring() {
        LocalDate today = today();
        return acceptances.findExpiringBetween(today, today.plusDays(props.exceptions().expiringWindow().toDays()))
                .stream().map(this::toView).toList();
    }

    private View view(long id) {
        return tx.execute(s -> toView(acceptances.findById(id).orElseThrow()));
    }

    private View toView(RiskAcceptance r) {
        String state = r.getRevokedAt() != null ? "REVOKED" : r.isActive(today()) ? "ACTIVE" : "EXPIRED";
        return new View(r.getId(), r.getProject().getKey(), r.getAdvisoryRef(), r.getModule(), r.getReason(),
                r.getExpiresOn().toString(), r.getRequestedBy(), state, findings.countByAcceptance(r),
                r.getCreatedAt().toString(), r.getRevokedAt() == null ? null : r.getRevokedAt().toString());
    }

    private Project project(String key) {
        return projects.findByKey(key).orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "프로젝트 없음: " + key));
    }

    private LocalDate today() {
        return LocalDate.ofInstant(clock.instant(), ZoneOffset.UTC);
    }
}
