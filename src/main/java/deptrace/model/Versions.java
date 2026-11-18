package deptrace.model;

import java.util.Comparator;

import org.apache.maven.artifact.versioning.ComparableVersion;
import org.apache.maven.artifact.versioning.DefaultArtifactVersion;
import org.apache.maven.artifact.versioning.InvalidVersionSpecificationException;
import org.apache.maven.artifact.versioning.VersionRange;

/**
 * Maven 버전 규칙을 따르는 비교·범위 판정. 규칙은 직접 구현하지 않고 Maven의 기준 구현(maven-artifact)을 사용한다.
 * (예: 1.0-alpha < 1.0-rc < 1.0 = 1.0.0 = 1.0.Final, 9.37 < 9.37.3)
 */
public final class Versions {

    public static final Comparator<String> MAVEN_ORDER = Comparator.comparing(ComparableVersion::new);

    private Versions() {
    }

    public static int compare(String a, String b) {
        return MAVEN_ORDER.compare(a, b);
    }

    /** "[1.3.3,2.4.10]", "(,2.0)" 같은 Maven 버전 범위 표기인지 여부. */
    public static boolean isRange(String spec) {
        return spec != null && (spec.startsWith("[") || spec.startsWith("("));
    }

    /** 범위 표기가 주어진 버전을 포함하는지. 해석할 수 없는 표기는 포함하는 것으로 본다(오탐 방지). */
    public static boolean rangeContains(String rangeSpec, String version) {
        try {
            return VersionRange.createFromVersionSpec(rangeSpec).containsVersion(new DefaultArtifactVersion(version));
        } catch (InvalidVersionSpecificationException e) {
            return true;
        }
    }

    /** 릴리스 라인 표기: "6.2.19" → "6.2.x". 숫자 두 자리가 없으면 원래 값. */
    public static String line(String version) {
        String[] parts = version.split("\\.");
        return parts.length >= 2 ? parts[0] + "." + parts[1] + ".x" : version;
    }

    /** 범위가 아니고 비어 있지 않은 고정 버전 요청인지. Gradle rich version 표기("{strictly ...}")는 제외한다. */
    public static boolean isExact(String spec) {
        return spec != null && !spec.isBlank() && !isRange(spec) && !spec.startsWith("{") && !spec.contains("+");
    }
}
