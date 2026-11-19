package deptrace.server.ingest;

import java.time.Clock;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

import deptrace.model.Coordinate;
import deptrace.server.config.DeptraceProperties;
import deptrace.server.domain.Component;
import deptrace.server.domain.ComponentRepository;
import deptrace.server.domain.Finding;
import deptrace.server.domain.Project;
import deptrace.server.domain.ProjectRepository;
import deptrace.server.domain.Snapshot;
import deptrace.server.domain.SnapshotRepository;
import deptrace.server.notify.Notifier;
import deptrace.server.scan.FindingReconciler;
import deptrace.server.scan.ScanService;

/**
 * SBOM 업로드 처리. 세 단계를 각각의 트랜잭션으로 나눈다.
 * <ol>
 *   <li>스냅샷 저장 (짧은 트랜잭션)</li>
 *   <li>최근에 조회하지 않은 구성요소만 OSV 조회 (트랜잭션 밖) → 대응 저장</li>
 *   <li>발견 상태 맞추기 (짧은 트랜잭션)</li>
 * </ol>
 */
@Service
public class SbomIngestService {

    /** accepted: 예외가 있어 열리지 않고 바로 수용된 발견 수. */
    public record Result(String project, long snapshotId, int components, int scanned, int skippedNonMaven,
                         int opened, int reopened, int resolved, int accepted) {
    }

    private final ProjectRepository projects;
    private final ComponentRepository components;
    private final SnapshotRepository snapshots;
    private final ScanService scanner;
    private final FindingReconciler reconciler;
    private final Notifier notifier;
    private final TransactionTemplate tx;
    private final DeptraceProperties props;
    private final Clock clock;

    public SbomIngestService(ProjectRepository projects, ComponentRepository components, SnapshotRepository snapshots,
                             ScanService scanner, FindingReconciler reconciler, Notifier notifier, TransactionTemplate tx,
                             DeptraceProperties props, Clock clock) {
        this.projects = projects;
        this.components = components;
        this.snapshots = snapshots;
        this.scanner = scanner;
        this.reconciler = reconciler;
        this.notifier = notifier;
        this.tx = tx;
        this.props = props;
        this.clock = clock;
    }

    public Result ingest(String projectKey, byte[] sbom) {
        CycloneDxReader.Parsed parsed = CycloneDxReader.read(sbom);
        Instant now = clock.instant();

        // 1. 스냅샷 저장
        record Saved(Project project, Snapshot snapshot, List<Component> toScan) {
        }
        Saved saved = tx.execute(status -> {
            Project project = projects.findByKey(projectKey).orElseGet(() -> projects.save(new Project(projectKey, now)));
            Set<Component> all = upsertComponents(parsed.components());
            Snapshot snapshot = snapshots.save(new Snapshot(project, all, parsed.tool(), now));
            project.replaceSnapshot(snapshot);
            List<Component> toScan = all.stream().filter(c -> c.needsScan(now, props.rescan().freshFor())).toList();
            return new Saved(project, snapshot, toScan);
        });

        // 2. OSV 조회는 트랜잭션 밖에서 (ScanService가 저장만 따로 트랜잭션으로 묶는다)
        ScanService.Result scan = scanner.scan(saved.toScan());

        // 3. 발견 상태 맞추기
        FindingReconciler.Result r = reconciler.reconcile(saved.project(), Finding.DetectedBy.UPLOAD);
        notifier.send(r.alerts());

        return new Result(projectKey, saved.snapshot().getId(), parsed.components().size(), scan.scanned(),
                parsed.skipped(), r.opened(), r.reopened(), r.resolved(), r.accepted());
    }

    /** 이미 있는 구성요소는 재사용하고 없는 것만 만든다. purl이 고유 키다. */
    private Set<Component> upsertComponents(Set<Coordinate> coordinates) {
        Map<String, Coordinate> byPurl = new LinkedHashMap<>();
        coordinates.forEach(c -> byPurl.put(c.purl(), c));
        Map<String, Component> existing = new LinkedHashMap<>();
        components.findByPurlIn(byPurl.keySet()).forEach(c -> existing.put(c.getPurl(), c));
        Set<Component> out = new LinkedHashSet<>();
        byPurl.forEach((purl, c) -> out.add(existing.computeIfAbsent(purl, p -> components.save(new Component(c)))));
        return out;
    }
}
