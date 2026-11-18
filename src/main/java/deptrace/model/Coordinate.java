package deptrace.model;

import java.util.Optional;

/**
 * Maven 좌표(group:artifact:version). 구성요소를 식별하는 기준 키이며 OSV 조회 시 purl로 변환한다.
 */
public record Coordinate(String group, String artifact, String version) {

    /** Gradle 구성요소 표기("group:name:version")를 좌표로 변환한다. 프로젝트 구성요소는 좌표가 없다. */
    public static Optional<Coordinate> parse(String notation) {
        if (notation == null || notation.startsWith("project ") || notation.startsWith("root project")) {
            return Optional.empty();
        }
        String[] parts = notation.split(":");
        if (parts.length < 3 || parts[0].isBlank() || parts[1].isBlank() || parts[2].isBlank()) {
            return Optional.empty();
        }
        return Optional.of(new Coordinate(parts[0], parts[1], parts[2]));
    }

    public String module() {
        return group + ":" + artifact;
    }

    /** package-url 명세의 Maven 표기. */
    public String purl() {
        return "pkg:maven/" + group + "/" + artifact + "@" + version;
    }

    @Override
    public String toString() {
        return module() + ":" + version;
    }
}
