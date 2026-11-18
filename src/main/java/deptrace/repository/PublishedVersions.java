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

    /** minimum 이상에서 배포된 가장 낮은 정식 버전. minimum 자체가 사전 배포 표기면 사전 배포도 허용한다. */
    default Optional<String> lowestPublishedAtLeast(String module, String minimum) {
        boolean allowPreRelease = PRE_RELEASE.matcher(minimum).matches();
        return versions(module).flatMap(list -> list.stream()
                .filter(v -> allowPreRelease || !PRE_RELEASE.matcher(v).matches())
                .filter(v -> Versions.compare(v, minimum) >= 0)
                .min(Versions.MAVEN_ORDER));
    }

    /** 조회하지 않는 구현(오프라인·테스트용). */
    PublishedVersions NONE = module -> Optional.empty();
}
