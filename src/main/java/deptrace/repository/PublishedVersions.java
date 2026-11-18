package deptrace.repository;

import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;

import deptrace.model.Versions;

/**
 * 저장소에 실제로 배포된 버전 목록.
 *
 * <p>OSV의 fixed 이벤트는 "이 버전부터 고쳐졌다"는 뜻일 뿐, 그 버전이 배포됐다는 보장은 없다.
 * (예: Tomcat 10.1.58은 수정 버전으로 기록돼 있지만 Maven Central에는 10.1.57 다음이 10.1.59다.)
 * 그대로 권고하면 빌드가 실패하므로, 수정 버전 이상에서 실제로 배포된 가장 낮은 정식 버전을 찾는다.
 */
public interface PublishedVersions {

    /** 사전 배포 버전 표기 (1.0-M1, 1.0-RC2, 1.0.Beta1, 1.0-alpha, -SNAPSHOT 등). */
    Pattern PRE_RELEASE = Pattern.compile("(?i).*[.-](alpha|beta|rc|cr|m|milestone|preview|ea|snapshot)[.-]?\\d*([.-].*)?$");

    /** 모듈의 배포 버전 목록. 조회할 수 없으면 empty. */
    Optional<List<String>> versions(String module);

    /**
     * 같은 버전 번호를 여러 변형으로 배포할 때 붙는 꼬리표 (guava 33.7.2-jre / 33.7.2-android, mssql-jdbc 12.8.1.jre11 등).
     * 정식 버전 표기(Final, RELEASE, GA)와 사전 배포 표기는 변형이 아니다.
     */
    Pattern FLAVOR = Pattern.compile("(?<=\\d)[.-]([A-Za-z][A-Za-z0-9_]*)$");
    Pattern RELEASE_MARKER = Pattern.compile("(?i)final|release|ga");

    /** 버전의 변형 꼬리표. 없으면 빈 문자열. */
    static String flavor(String version) {
        if (PRE_RELEASE.matcher(version).matches()) {
            return "";
        }
        var m = FLAVOR.matcher(version);
        if (!m.find() || RELEASE_MARKER.matcher(m.group(1)).matches()) {
            return "";
        }
        return m.group(1).toLowerCase();
    }

    /** minimum 이상에서 배포된 가장 낮은 정식 버전. minimum 자체가 사전 배포 표기면 사전 배포도 허용한다. */
    default Optional<String> lowestPublishedAtLeast(String module, String minimum) {
        return lowestPublishedAtLeast(module, minimum, null);
    }

    /**
     * minimum 이상에서 배포된 가장 낮은 정식 버전을 고르되, current와 같은 변형을 우선한다.
     *
     * <p>Maven 버전 비교에서 한정자는 사전순이라 33.7.2-android가 33.7.2-jre보다 낮다.
     * 변형을 보지 않으면 -jre를 쓰는 프로젝트에 -android를 권고하게 되므로, 같은 변형이 배포돼 있으면 그중에서 고른다.
     * 같은 변형이 없을 때만 다른 변형으로 넘어간다.
     */
    default Optional<String> lowestPublishedAtLeast(String module, String minimum, String current) {
        boolean allowPreRelease = PRE_RELEASE.matcher(minimum).matches();
        Optional<List<String>> candidates = versions(module).map(list -> list.stream()
                .filter(v -> allowPreRelease || !PRE_RELEASE.matcher(v).matches())
                .filter(v -> Versions.compare(v, minimum) >= 0)
                .toList());
        if (candidates.isEmpty()) {
            return Optional.empty();
        }
        if (current != null) {
            String wanted = flavor(current);
            Optional<String> sameFlavor = candidates.get().stream()
                    .filter(v -> flavor(v).equals(wanted))
                    .min(Versions.MAVEN_ORDER);
            if (sameFlavor.isPresent()) {
                return sameFlavor;
            }
        }
        return candidates.get().stream().min(Versions.MAVEN_ORDER);
    }

    /** 조회하지 않는 구현(오프라인·테스트용). */
    PublishedVersions NONE = module -> Optional.empty();
}
