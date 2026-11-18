package deptrace.analysis;

import java.util.List;

/**
 * 구성요소의 버전이 "왜" 그렇게 결정됐는지에 대한 분류.
 *
 * @param requestedVersions 이 구성요소를 끌어온 엣지들이 요청한 버전(직접 선언 포함, 범위·빈 값 제외 안 함)
 * @param downgraded        누군가 요청한 고정 버전보다 낮은 버전이 선택됨 (Gradle 기본 충돌 해결에서는 일어나지 않음)
 * @param outOfRange        요청한 버전 범위 밖의 버전이 선택된 요청들
 */
public record VersionDecision(
        Kind kind,
        String selected,
        String declared,
        String managed,
        List<String> requestedVersions,
        boolean downgraded,
        List<String> outOfRange,
        String explanation) {

    public enum Kind {
        /** 빌드 스크립트에 직접 선언한 버전이 그대로 선택됨 */
        DIRECT,
        /** 직접 선언한 버전이 BOM 관리 버전이나 다른 라이브러리의 요청을 덮어씀 */
        DIRECT_OVERRIDE,
        /** BOM(dependency-management 플러그인) 규칙이 버전을 결정 */
        BOM_MANAGED,
        /** 여러 요청 중 Gradle 충돌 해결(최고 버전)로 결정 */
        CONFLICT_RESOLUTION,
        /** platform/constraint 제약으로 결정 */
        CONSTRAINT,
        /** force 설정으로 강제 */
        FORCED,
        /** 전이 의존성이 요청한 버전 그대로 */
        TRANSITIVE
    }
}
