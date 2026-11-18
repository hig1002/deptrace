package deptrace.license;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import deptrace.license.Pom.DeclaredLicense;
import deptrace.model.Coordinate;

/**
 * 구성요소 하나의 라이선스를 판정한다.
 *
 * <p>여러 라이선스가 선언돼 있으면 "그중 하나를 골라 쓸 수 있다"(OR)로 본다. Maven 모델 레퍼런스(licenses)가
 * 다중 라이선스를 그렇게 정의하고, 실제로 logback(EPL-1.0 / LGPL-2.1), jakarta.*(EPL-2.0 / GPL2 w/ CPE)처럼
 * 이중 라이선스를 나열하는 용도로 쓰인다. 그래서 판정 분류는 식별된 것 중 가장 제약이 적은 것으로 하되,
 * 이 가정을 결과에 남겨 사람이 확인할 수 있게 한다.
 */
public final class LicenseResolver {

    /** 부모 POM을 몇 단계까지 따라갈지. 실제로는 3~4단계면 끝나고, 순환·비정상 체인을 막기 위한 상한이다. */
    private static final int MAX_PARENT_DEPTH = 10;

    public enum Status {
        /** 자기 POM에 선언 */
        DECLARED,
        /** 부모 POM에서 상속 */
        INHERITED,
        /** 부모 체인 끝까지 선언 없음 */
        NOT_DECLARED,
        /** POM을 받지 못함 */
        POM_UNAVAILABLE
    }

    /**
     * @param declared   POM에 적힌 원문
     * @param declaredIn 선언을 찾은 POM 좌표 (상속이면 부모)
     * @param spdx       식별된 SPDX 식별자. 식별 못 한 선언은 빠진다
     * @param unmatched  식별하지 못한 선언 원문
     * @param category   판정 분류. 식별된 것이 하나도 없으면 UNKNOWN
     */
    public record ComponentLicense(String coordinate, String module, Status status, String declaredIn,
                                   List<DeclaredLicense> declared, List<String> spdx, List<String> unmatched,
                                   LicenseCategory category, boolean multiple) {

        public String expression() {
            return spdx.isEmpty() ? "NOASSERTION" : String.join(" OR ", spdx);
        }
    }

    private final PomSource poms;

    public LicenseResolver(PomSource poms) {
        this.poms = poms;
    }

    public ComponentLicense resolve(Coordinate coordinate) {
        Coordinate current = coordinate;
        Set<Coordinate> seen = new HashSet<>();
        for (int depth = 0; depth <= MAX_PARENT_DEPTH && current != null && seen.add(current); depth++) {
            Optional<String> xml = poms.pom(current);
            if (xml.isEmpty()) {
                return depth == 0
                        ? result(coordinate, Status.POM_UNAVAILABLE, null, List.of())
                        : result(coordinate, Status.NOT_DECLARED, null, List.of());
            }
            Pom pom;
            try {
                pom = Pom.parse(xml.get());
            } catch (IllegalArgumentException e) {
                return result(coordinate, depth == 0 ? Status.POM_UNAVAILABLE : Status.NOT_DECLARED, null, List.of());
            }
            if (!pom.licenses().isEmpty()) {
                return result(coordinate, depth == 0 ? Status.DECLARED : Status.INHERITED, current, pom.licenses());
            }
            current = pom.parent().orElse(null);
        }
        return result(coordinate, Status.NOT_DECLARED, null, List.of());
    }

    static ComponentLicense result(Coordinate c, Status status, Coordinate declaredIn, List<DeclaredLicense> declared) {
        List<String> spdx = new ArrayList<>();
        List<String> unmatched = new ArrayList<>();
        List<LicenseCategory> categories = new ArrayList<>();
        for (DeclaredLicense d : declared) {
            Optional<SpdxCatalog.License> id = SpdxCatalog.identify(d);
            if (id.isPresent()) {
                if (!spdx.contains(id.get().id())) {
                    spdx.add(id.get().id());
                    categories.add(id.get().category());
                }
            } else {
                unmatched.add(d.name() != null ? d.name() : d.url());
            }
        }
        LicenseCategory category = categories.stream().min(Comparator.naturalOrder()).orElse(LicenseCategory.UNKNOWN);
        return new ComponentLicense(c.toString(), c.module(), status, declaredIn == null ? null : declaredIn.toString(),
                declared, spdx, unmatched, category, declared.size() > 1);
    }
}
