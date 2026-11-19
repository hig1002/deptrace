package deptrace.server.scan;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import deptrace.model.Coordinate;
import deptrace.osv.OsvVulnerability;
import deptrace.osv.VulnerabilitySource;
import deptrace.server.domain.Advisory;
import deptrace.server.domain.AdvisoryRepository;
import deptrace.server.domain.Component;
import deptrace.server.domain.ComponentAdvisory;
import deptrace.server.domain.ComponentAdvisoryRepository;
import deptrace.server.domain.ComponentRepository;

/**
 * 구성요소 버전을 OSV와 대조해 (구성요소, 권고) 대응을 갱신한다.
 *
 * <p>OSV 조회(네트워크)는 트랜잭션 밖에서 하고, 결과 저장만 짧은 트랜잭션으로 한다.
 * 조회 중에 DB 커넥션을 잡고 있으면, 외부 API가 느려질 때 커넥션 풀이 먼저 고갈된다.
 */
@Service
public class ScanService {

    /** changed: 새로 걸린 대응, removed: 철회·범위 수정으로 더 이상 걸리지 않는 대응. */
    public record Result(int scanned, List<ComponentAdvisory.Key> added, List<ComponentAdvisory.Key> removed) {
    }

    private final VulnerabilitySource osv;
    private final Writer writer;

    public ScanService(VulnerabilitySource osv, Writer writer) {
        this.osv = osv;
        this.writer = writer;
    }

    /** 트랜잭션 없이 호출한다 (조회 → 저장). 이미 트랜잭션 안이면 저장은 그 트랜잭션에 참여한다. */
    public Result scan(Collection<Component> components) {
        if (components.isEmpty()) {
            return new Result(0, List.of(), List.of());
        }
        Map<Coordinate, Long> idOf = new LinkedHashMap<>();
        components.forEach(c -> idOf.put(c.coordinate(), c.getId()));
        Map<Coordinate, List<OsvVulnerability>> found = osv.vulnerabilities(idOf.keySet());

        Map<Long, List<OsvVulnerability>> byComponent = new LinkedHashMap<>();
        idOf.forEach((coordinate, id) -> byComponent.put(id, found.getOrDefault(coordinate, List.of())));
        return writer.save(byComponent);
    }

    /** 프록시를 거쳐야 @Transactional이 적용되므로 별도 빈으로 둔다. */
    @Service
    public static class Writer {

        private final ComponentRepository components;
        private final AdvisoryRepository advisories;
        private final ComponentAdvisoryRepository links;
        private final Clock clock;

        public Writer(ComponentRepository components, AdvisoryRepository advisories, ComponentAdvisoryRepository links, Clock clock) {
            this.components = components;
            this.advisories = advisories;
            this.links = links;
            this.clock = clock;
        }

        @Transactional
        public Result save(Map<Long, List<OsvVulnerability>> byComponent) {
            Instant now = clock.instant();
            // 권고 원문 갱신 (같은 권고가 여러 구성요소에 걸려도 한 번만)
            Map<String, OsvVulnerability> unique = new LinkedHashMap<>();
            byComponent.values().forEach(list -> list.forEach(v -> unique.putIfAbsent(v.id(), v)));
            Map<String, Advisory> existing = advisories.findAllById(unique.keySet()).stream()
                    .collect(Collectors.toMap(Advisory::getId, a -> a));
            unique.forEach((id, v) -> existing.computeIfAbsent(id, Advisory::new).update(v, now));
            advisories.saveAll(existing.values());

            Map<Long, Set<String>> current = links.findByKeyComponentIdIn(byComponent.keySet()).stream()
                    .collect(Collectors.groupingBy(l -> l.getKey().componentId(),
                            Collectors.mapping(l -> l.getKey().advisoryId(), Collectors.toSet())));
            List<ComponentAdvisory.Key> added = new ArrayList<>();
            List<ComponentAdvisory.Key> removed = new ArrayList<>();
            List<ComponentAdvisory> toInsert = new ArrayList<>();
            byComponent.forEach((componentId, vulns) -> {
                Set<String> before = current.getOrDefault(componentId, Set.of());
                Set<String> after = vulns.stream().map(OsvVulnerability::id).collect(Collectors.toSet());
                after.stream().filter(id -> !before.contains(id)).forEach(id -> {
                    toInsert.add(new ComponentAdvisory(componentId, id, now));
                    added.add(new ComponentAdvisory.Key(componentId, id));
                });
                before.stream().filter(id -> !after.contains(id))
                        .forEach(id -> removed.add(new ComponentAdvisory.Key(componentId, id)));
            });
            links.saveAll(toInsert);
            links.deleteAllById(removed);
            components.findAllById(byComponent.keySet()).forEach(c -> c.markScanned(now));
            return new Result(byComponent.size(), added, removed);
        }
    }
}
