package deptrace.osv;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;

import deptrace.model.Coordinate;
import deptrace.model.Versions;

/**
 * OSV 영향 범위(ECOSYSTEM 타입)에서 수정 버전을 구한다.
 *
 * <p>범위는 이벤트를 Maven 버전 순으로 정렬해 상태 기계로 해석한다.
 * introduced → 영향 시작, fixed → 해당 버전부터 안전, last_affected → 해당 버전까지 영향. "0"은 모든 버전보다 앞선다.
 *
 * <p>권고는 릴리스 라인마다 범위를 따로 둔다(예: Spring 6.1.0~6.1.21 last_affected, 6.2.0~6.2.19 fixed).
 * 현재 라인에 공개 수정 버전이 없으면 "같은 라인 수정 버전"은 없고, 다음 라인의 fixed 중 다른 범위에도 걸리지 않는
 * 가장 낮은 버전이 "안전한 다음 버전"이 된다. 둘을 구분해야 패치 업그레이드로 끝나는지, 라인을 옮겨야 하는지 판단할 수 있다.
 */
public final class FixVersionResolver {

    /**
     * @param sameLine     현재 버전이 속한 범위를 닫는 fixed 버전 (없으면 null)
     * @param nextSafe     현재보다 높고 어떤 영향 범위에도 속하지 않는 가장 낮은 fixed 버전 (없으면 null)
     * @param alternatives 같은 권고가 다른 좌표(같은 artifactId)에는 수정 버전을 둔 경우 "group:artifact:fixed" — 좌표 이동·포크 단서
     */
    public record FixInfo(String sameLine, String nextSafe, List<String> alternatives) {

        public boolean requiresLineChange() {
            return sameLine == null && nextSafe != null;
        }
    }

    private FixVersionResolver() {
    }

    public static FixInfo resolve(OsvVulnerability vulnerability, Coordinate coordinate) {
        String current = coordinate.version();
        List<OsvVulnerability.Range> ranges = new ArrayList<>();
        List<String> alternatives = new ArrayList<>();
        for (OsvVulnerability.Affected affected : vulnerability.affected()) {
            if (!"Maven".equals(affected.ecosystem())) {
                continue;
            }
            List<OsvVulnerability.Range> ecosystemRanges = affected.ranges().stream()
                    .filter(r -> "ECOSYSTEM".equals(r.type())).toList();
            if (coordinate.module().equals(affected.name())) {
                ranges.addAll(ecosystemRanges);
            } else if (affected.name().endsWith(":" + coordinate.artifact())) {
                ecosystemRanges.stream().flatMap(r -> r.events().stream())
                        .filter(e -> e.type().equals("fixed"))
                        .map(OsvVulnerability.Event::version)
                        .max(Versions.MAVEN_ORDER)
                        .ifPresent(v -> alternatives.add(affected.name() + ":" + v));
            }
        }

        String sameLine = ranges.stream().map(r -> fixWithin(r, current)).flatMap(Optional::stream)
                .min(Versions.MAVEN_ORDER).orElse(null);
        String nextSafe = ranges.stream().flatMap(r -> r.events().stream())
                .filter(e -> e.type().equals("fixed"))
                .map(OsvVulnerability.Event::version)
                .filter(v -> compareEventVersion(v, current) > 0)
                .filter(v -> ranges.stream().noneMatch(r -> affects(r, v)))
                .min(Versions.MAVEN_ORDER).orElse(null);
        return new FixInfo(sameLine, nextSafe, alternatives.stream().distinct().sorted().toList());
    }

    /** 현재 버전이 이 범위 안에 있으면 범위를 닫는 fixed 버전. */
    static Optional<String> fixWithin(OsvVulnerability.Range range, String current) {
        boolean affected = false;
        for (OsvVulnerability.Event e : sorted(range)) {
            int cmp = compareEventVersion(e.version(), current);
            if (cmp > 0) {
                return affected && e.type().equals("fixed") ? Optional.of(e.version()) : Optional.empty();
            }
            affected = transition(affected, e, cmp);
        }
        return Optional.empty();
    }

    /** 버전이 이 범위의 영향을 받는지. */
    static boolean affects(OsvVulnerability.Range range, String version) {
        boolean affected = false;
        for (OsvVulnerability.Event e : sorted(range)) {
            int cmp = compareEventVersion(e.version(), version);
            if (cmp > 0) {
                break;
            }
            affected = transition(affected, e, cmp);
        }
        return affected;
    }

    private static boolean transition(boolean affected, OsvVulnerability.Event e, int cmpToTarget) {
        return switch (e.type()) {
            case "introduced" -> true;
            case "fixed" -> false;
            case "last_affected" -> cmpToTarget == 0;
            default -> affected;
        };
    }

    private static List<OsvVulnerability.Event> sorted(OsvVulnerability.Range range) {
        List<OsvVulnerability.Event> events = new ArrayList<>(range.events());
        events.removeIf(e -> e.type().equals("limit"));
        events.sort(Comparator.comparing(OsvVulnerability.Event::version, FixVersionResolver::compareEventVersion));
        return events;
    }

    private static int compareEventVersion(String a, String b) {
        if (a.equals(b)) {
            return 0;
        }
        if (a.equals("0")) {
            return -1;
        }
        if (b.equals("0")) {
            return 1;
        }
        return Versions.compare(a, b);
    }
}
