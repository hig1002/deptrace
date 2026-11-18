package deptrace.analysis;

import java.util.List;
import java.util.stream.Stream;

import deptrace.model.Versions;

/**
 * 버전 결정 원인에 따라 "어디를 고쳐야 그 버전이 바뀌는가"를 정한다.
 * 같은 취약점이라도 버전을 결정한 주체(직접 선언, BOM, 충돌 해결)가 다르면 수정 지점이 다르다.
 */
public record Remediation(Category category, String advice) {

    public enum Category {
        /** 직접 선언을 지우면 BOM·다른 라이브러리가 요청한 안전한 버전이 선택된다 */
        REMOVE_DIRECT_PIN,
        /** 직접 선언한 버전을 올린다 */
        UPDATE_DIRECT,
        /** BOM이 관리하는 버전: Spring Boot 업그레이드 또는 BOM 버전 속성 오버라이드 */
        UPGRADE_PLATFORM,
        /** 전이 의존성: 유입자 업그레이드 또는 constraints로 하한 지정 */
        CONSTRAIN_TRANSITIVE,
        /** 같은 좌표에는 수정 버전이 없다: 제거·대체 또는 근거를 남긴 예외 */
        NO_FIX,
        /** 배포물에 들어가지 않는 테스트 범위 */
        TEST_ONLY
    }

    /**
     * @param fixVersion   모든 권고를 해소하는 최소 버전(권고별 안전한 다음 버전 중 최댓값). 없으면 null.
     * @param lineChange   현재 릴리스 라인에는 공개 수정 버전이 없어 다음 라인으로 옮겨야 하는 권고가 있음
     * @param alternatives 수정 버전이 없는 권고가 다른 좌표에 둔 수정 버전
     * @param introducers  1차 유입자(직접 의존성)
     */
    public static Remediation advise(VersionDecision decision, boolean inPrimary, String fixVersion, boolean allFixable,
                                     boolean lineChange, List<String> alternatives, String module, List<String> introducers) {
        return advise(decision, inPrimary, fixVersion, allFixable, lineChange, alternatives, module, introducers, false);
    }

    /** maven=true면 수정 방법을 pom.xml 기준(dependencyManagement, 부모 POM 속성)으로 안내한다. */
    public static Remediation advise(VersionDecision decision, boolean inPrimary, String fixVersion, boolean allFixable,
                                     boolean lineChange, List<String> alternatives, String module, List<String> introducers,
                                     boolean maven) {
        if (!inPrimary) {
            return new Remediation(Category.TEST_ONLY, "배포 클래스패스에 없음(테스트 범위). 게이트 대상에서 제외하고 보고만 한다.");
        }
        String moved = alternatives.isEmpty() ? ""
                : " 같은 권고가 다른 좌표에는 수정 버전을 두고 있다(" + String.join(", ", alternatives) + "): 좌표 이동·포크 여부를 확인한다.";
        if (fixVersion == null) {
            return new Remediation(Category.NO_FIX, "이 좌표에는 공개된 수정 버전이 없다." + moved
                    + " 실제 사용 여부를 확인해 제거·대체하거나, 영향이 없다는 근거와 만료일을 남겨 예외로 등록한다.");
        }
        String notes = (lineChange ? " 현재 릴리스 라인에는 공개 수정 버전이 없어 " + Versions.line(fixVersion) + " 라인으로 옮겨야 한다." : "")
                + (allFixable ? "" : " 일부 권고는 수정 버전이 없다." + moved);

        return switch (decision.kind()) {
            case DIRECT_OVERRIDE -> {
                String alternative = Stream.concat(Stream.ofNullable(decision.managed()),
                                decision.requestedVersions().stream().filter(Versions::isExact))
                        .filter(v -> !v.equals(decision.declared()))
                        .max(Versions.MAVEN_ORDER).orElse(null);
                if (alternative != null && Versions.compare(alternative, fixVersion) >= 0) {
                    yield new Remediation(Category.REMOVE_DIRECT_PIN, "직접 선언(" + module + ":" + decision.declared()
                            + ")을 제거하면 " + alternative + "이 선택되어 해소된다. 코드에서 직접 쓰지 않는다면 선언 자체가 불필요하다." + notes);
                }
                String partial = alternative == null ? ""
                        : " 직접 선언을 제거하면 " + alternative + "이 선택되지만 " + fixVersion + " 미만이라 일부 권고가 남는다.";
                yield new Remediation(Category.UPDATE_DIRECT, "직접 선언 버전을 " + fixVersion + " 이상으로 올린다." + partial + notes);
            }
            case DIRECT -> new Remediation(Category.UPDATE_DIRECT, "직접 선언 버전을 " + fixVersion + " 이상으로 올린다." + notes);
            case BOM_MANAGED -> new Remediation(Category.UPGRADE_PLATFORM, maven
                    ? "dependencyManagement(부모 POM·BOM import)가 관리하는 버전이다. " + fixVersion + " 이상을 관리하는 부모 POM·BOM으로 올리거나, "
                            + "부모가 제공하는 버전 속성(<properties>)이나 <dependencyManagement> 항목으로 오버라이드한다(검증된 조합이 깨지므로 근거를 남긴다)." + notes
                    : "Spring Boot BOM이 관리하는 버전이다. " + fixVersion + " 이상을 관리하는 Spring Boot로 올리거나, "
                            + "BOM 버전 속성으로 오버라이드한다(검증된 조합이 깨지므로 근거를 남긴다)." + notes);
            default -> new Remediation(Category.CONSTRAIN_TRANSITIVE, maven
                    ? "전이 의존성이다. 유입자(" + String.join(", ", introducers) + ")를 올리거나, <dependencyManagement>에 "
                            + module + ":" + fixVersion + "을 선언해 고정한다. Maven은 nearest-wins라 다른 경로에서 더 높은 버전을 요청해도 "
                            + "자동으로 올라가지 않는다." + notes
                    : "전이 의존성이다. 유입자(" + String.join(", ", introducers) + ")를 올리거나, "
                            + "constraints { implementation('" + module + ":" + fixVersion + "') } 로 하한을 지정한다." + notes);
        };
    }
}
