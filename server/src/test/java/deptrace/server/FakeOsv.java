package deptrace.server;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import deptrace.model.Coordinate;
import deptrace.osv.OsvVulnerability;
import deptrace.osv.Severity;
import deptrace.osv.VulnerabilitySource;

/** 테스트용 OSV. 권고를 "공개"하거나 "철회"하고, 몇 개의 좌표를 물었는지 센다. */
public class FakeOsv implements VulnerabilitySource {

    private final Map<String, List<OsvVulnerability>> byModuleVersion = new ConcurrentHashMap<>();
    private final List<Coordinate> asked = new ArrayList<>();

    public synchronized void publish(String coordinate, String id, String alias, Severity severity) {
        byModuleVersion.computeIfAbsent(coordinate, k -> new ArrayList<>())
                .add(new OsvVulnerability(id, "summary of " + id, alias == null ? List.of() : List.of(alias), "2026-11-18T00:00:00Z",
                        null, severity, List.of()));
    }

    public synchronized void withdraw(String coordinate, String id) {
        byModuleVersion.getOrDefault(coordinate, new ArrayList<>()).removeIf(v -> v.id().equals(id));
    }

    public synchronized void reset() {
        byModuleVersion.clear();
        asked.clear();
    }

    public synchronized int askedCount() {
        return asked.size();
    }

    public synchronized void clearAsked() {
        asked.clear();
    }

    @Override
    public synchronized Map<Coordinate, List<OsvVulnerability>> vulnerabilities(Collection<Coordinate> coordinates) {
        asked.addAll(coordinates);
        Map<Coordinate, List<OsvVulnerability>> out = new LinkedHashMap<>();
        for (Coordinate c : coordinates) {
            List<OsvVulnerability> v = byModuleVersion.get(c.toString());
            if (v != null && !v.isEmpty()) {
                out.put(c, List.copyOf(v));
            }
        }
        return out;
    }
}
