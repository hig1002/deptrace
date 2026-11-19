package deptrace.server.scan;

import java.time.Clock;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import deptrace.server.domain.Advisory;
import deptrace.server.domain.AdvisoryRepository;
import deptrace.server.domain.Component;
import deptrace.server.domain.ComponentAdvisory;
import deptrace.server.domain.ComponentAdvisoryRepository;
import deptrace.server.domain.ComponentRepository;
import deptrace.server.domain.Finding;
import deptrace.server.domain.FindingRepository;
import deptrace.server.domain.Project;
import deptrace.server.domain.RiskAcceptance;
import deptrace.server.domain.RiskAcceptanceRepository;
import deptrace.server.notify.Notifier;

/**
 * 프로젝트의 현재 스냅샷, (구성요소, 권고) 대응, 유효한 예외를 비교해 발견 상태를 맞춘다.
 *
 * <pre>
 * 해당함 + 유효한 예외 있음 → ACCEPTED (알리지 않음)
 * 해당함 + 예외 없음        → OPEN     (새로 열리면 알림. 예외가 끝나 다시 열려도 알림)
 * 해당하지 않음            → RESOLVED (구성요소 상향·제거, 권고 철회)
 * </pre>
 *
 * 같은 입력과 같은 날짜로 두 번 실행해도 결과가 같다(멱등). 예외 만료는 날짜가 바뀐 뒤의 실행(매일 재검사)이 처리한다.
 */
@Service
public class FindingReconciler {

    /**
     * alerts는 트랜잭션 안에서 만든다. 새 발견의 구성요소·권고는 지연 로딩 프록시라,
     * 트랜잭션이 끝난 뒤 읽으면 LazyInitializationException이 난다.
     */
    public record Result(int opened, int reopened, int resolved, int accepted, int acceptanceEnded, List<Notifier.Alert> alerts) {
    }

    private final ComponentAdvisoryRepository links;
    private final FindingRepository findings;
    private final ComponentRepository components;
    private final AdvisoryRepository advisories;
    private final RiskAcceptanceRepository acceptances;
    private final Clock clock;

    public FindingReconciler(ComponentAdvisoryRepository links, FindingRepository findings, ComponentRepository components,
                             AdvisoryRepository advisories, RiskAcceptanceRepository acceptances, Clock clock) {
        this.links = links;
        this.findings = findings;
        this.components = components;
        this.advisories = advisories;
        this.acceptances = acceptances;
        this.clock = clock;
    }

    @Transactional
    public Result reconcile(Project project, Finding.DetectedBy detectedBy) {
        Instant now = clock.instant();
        LocalDate today = LocalDate.ofInstant(now, ZoneOffset.UTC);
        Set<ComponentAdvisory.Key> desired = links.findForProject(project.getId()).stream()
                .map(ComponentAdvisory::getKey).collect(Collectors.toSet());
        Map<Long, Component> componentById = components.findAllById(desired.stream().map(ComponentAdvisory.Key::componentId).toList())
                .stream().collect(Collectors.toMap(Component::getId, Function.identity()));
        Map<String, Advisory> advisoryById = advisories.findAllById(desired.stream().map(ComponentAdvisory.Key::advisoryId).toList())
                .stream().collect(Collectors.toMap(Advisory::getId, Function.identity()));
        List<RiskAcceptance> active = acceptances.findActive(project, today);

        Map<ComponentAdvisory.Key, Finding> existing = new LinkedHashMap<>();
        for (Finding f : findings.findByProject(project)) {
            existing.put(new ComponentAdvisory.Key(f.getComponent().getId(), f.getAdvisory().getId()), f);
        }

        int opened = 0;
        int reopened = 0;
        int resolved = 0;
        int accepted = 0;
        int ended = 0;
        List<Finding> created = new ArrayList<>();
        List<Notifier.Alert> alerts = new ArrayList<>();
        for (ComponentAdvisory.Key key : desired) {
            Component component = componentById.get(key.componentId());
            Advisory advisory = advisoryById.get(key.advisoryId());
            Optional<RiskAcceptance> cover = active.stream().filter(r -> r.covers(component, advisory)).findFirst();
            Finding f = existing.get(key);
            if (f == null) {
                f = new Finding(project, component, advisory, detectedBy, now);
                created.add(f);
                if (cover.isPresent()) {
                    f.accept(cover.get(), now);
                    accepted++;
                } else {
                    opened++;
                    alerts.add(alert(project, f, detectedBy.name(), "NEW"));
                }
            } else if (cover.isPresent()) {
                if (f.getStatus() != Finding.Status.ACCEPTED) {
                    accepted++;
                }
                f.accept(cover.get(), now);
            } else if (f.getStatus() == Finding.Status.ACCEPTED) {
                f.endAcceptance(now);
                ended++;
                alerts.add(alert(project, f, detectedBy.name(), "ACCEPTANCE_ENDED"));
            } else if (f.getStatus() == Finding.Status.RESOLVED) {
                f.reopen(now);
                reopened++;
                alerts.add(alert(project, f, detectedBy.name(), "REOPENED"));
            }
        }
        for (Map.Entry<ComponentAdvisory.Key, Finding> e : existing.entrySet()) {
            Finding f = e.getValue();
            if (f.getStatus() != Finding.Status.RESOLVED && !desired.contains(e.getKey())) {
                f.resolve(now);
                resolved++;
            }
        }
        findings.saveAll(created);
        return new Result(opened, reopened, resolved, accepted, ended, alerts);
    }

    private static Notifier.Alert alert(Project project, Finding f, String detectedBy, String event) {
        return new Notifier.Alert(project.getKey(), f.getComponent().getPurl(), f.getAdvisory().getId(),
                String.valueOf(f.getAdvisory().getSeverity()), detectedBy, event);
    }
}
