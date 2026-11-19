package deptrace.server.scan;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import deptrace.server.domain.AdvisoryRepository;
import deptrace.server.domain.ComponentAdvisory;
import deptrace.server.domain.ComponentAdvisoryRepository;
import deptrace.server.domain.ComponentRepository;
import deptrace.server.domain.Finding;
import deptrace.server.domain.FindingRepository;
import deptrace.server.domain.Project;
import deptrace.server.notify.Notifier;

/**
 * 프로젝트의 현재 스냅샷과 (구성요소, 권고) 대응을 비교해 발견 상태를 맞춘다.
 * <ul>
 *   <li>있어야 하는데 없음 → 새 발견 (OPEN)</li>
 *   <li>있어야 하는데 RESOLVED → 다시 열림</li>
 *   <li>OPEN인데 더 이상 해당 없음 (구성요소 상향·제거, 권고 철회) → RESOLVED</li>
 * </ul>
 * 같은 입력으로 두 번 실행해도 결과가 같다(멱등). 재검사가 중간에 실패해 다시 돌려도 안전하다.
 */
@Service
public class FindingReconciler {

    /**
     * alerts는 트랜잭션 안에서 만든다. 새 발견의 구성요소·권고는 지연 로딩 프록시라,
     * 트랜잭션이 끝난 뒤 읽으면 LazyInitializationException이 난다.
     */
    public record Result(int opened, int reopened, int resolved, List<Notifier.Alert> alerts) {
    }

    private final ComponentAdvisoryRepository links;
    private final FindingRepository findings;
    private final ComponentRepository components;
    private final AdvisoryRepository advisories;
    private final Clock clock;

    public FindingReconciler(ComponentAdvisoryRepository links, FindingRepository findings, ComponentRepository components,
                             AdvisoryRepository advisories, Clock clock) {
        this.links = links;
        this.findings = findings;
        this.components = components;
        this.advisories = advisories;
        this.clock = clock;
    }

    @Transactional
    public Result reconcile(Project project, Finding.DetectedBy detectedBy) {
        Instant now = clock.instant();
        Set<ComponentAdvisory.Key> desired = links.findForProject(project.getId()).stream()
                .map(ComponentAdvisory::getKey).collect(Collectors.toSet());
        Map<ComponentAdvisory.Key, Finding> existing = new LinkedHashMap<>();
        for (Finding f : findings.findByProject(project)) {
            existing.put(new ComponentAdvisory.Key(f.getComponent().getId(), f.getAdvisory().getId()), f);
        }

        List<Finding> opened = new ArrayList<>();
        List<Finding> reopened = new ArrayList<>();
        List<Finding> resolved = new ArrayList<>();
        for (ComponentAdvisory.Key key : desired) {
            Finding f = existing.get(key);
            if (f == null) {
                opened.add(new Finding(project, components.getReferenceById(key.componentId()),
                        advisories.getReferenceById(key.advisoryId()), detectedBy, now));
            } else if (f.getStatus() == Finding.Status.RESOLVED) {
                f.reopen(now);
                reopened.add(f);
            }
        }
        existing.forEach((key, f) -> {
            if (f.getStatus() == Finding.Status.OPEN && !desired.contains(key)) {
                f.resolve(now);
                resolved.add(f);
            }
        });
        findings.saveAll(opened);
        List<Notifier.Alert> alerts = new ArrayList<>();
        for (Finding f : opened) {
            alerts.add(alert(project, f, detectedBy));
        }
        for (Finding f : reopened) {
            alerts.add(alert(project, f, detectedBy));
        }
        return new Result(opened.size(), reopened.size(), resolved.size(), alerts);
    }

    private static Notifier.Alert alert(Project project, Finding f, Finding.DetectedBy detectedBy) {
        return new Notifier.Alert(project.getKey(), f.getComponent().getPurl(), f.getAdvisory().getId(),
                String.valueOf(f.getAdvisory().getSeverity()), detectedBy.name());
    }
}
