package deptrace.nvd;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import deptrace.model.Versions;
import deptrace.nvd.NvdCve.Config;
import deptrace.nvd.NvdCve.CpeMatch;
import deptrace.nvd.NvdCve.Node;
import deptrace.repository.PublishedVersions;

/**
 * NVD 적용 조건(configurations)이 지금 클래스패스에 해당하는지 판정한다.
 *
 * <p>CPE 2.3: cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other.
 * <ul>
 *   <li>target_sw가 지정돼 있으면 Java 계열만 받아들인다. Dependency-Check는 이를 보지 않아 Go·Node.js용
 *       OpenTelemetry 권고를 Java jar에 붙였다.</li>
 *   <li>버전 "-"는 "해당 없음(NA)"이다. 모든 버전이 아니다. (예: RHEL Tomcat 패키지 권한 문제 CVE-2016-5425)</li>
 *   <li>AND 조건의 다른 항목은 클래스패스의 다른 제품 버전으로 확인한다. OS·JRE처럼 클래스패스로 알 수 없는 조건은
 *       만족하지 않는 것으로 본다. 확인할 수 없는 것을 해당한다고 보고하지 않기 위해서다.</li>
 * </ul>
 */
public final class CpeMatcher {

    /** target_sw가 이 값들이면 Java 라이브러리에 해당하는 조건으로 본다. "*"·"-"는 미지정. */
    private static final Set<String> JAVA_TARGETS = Set.of("*", "-", "java", "maven", "jvm");

    private CpeMatcher() {
    }

    /**
     * vendorProduct가 version일 때 이 CVE가 해당하면, 그 판단의 근거가 된 취약 조건을 돌려준다.
     *
     * @param context 클래스패스에 있는 제품들의 버전 ("vendor:product" → 버전들). AND 조건 확인용
     */
    public static Optional<CpeMatch> match(NvdCve cve, String vendorProduct, String version, Map<String, Set<String>> context) {
        String v = cpeVersion(version);
        for (Config config : cve.configs()) {
            // 이 설정에서 우리 제품·버전을 직접 지목하는 취약 조건
            Optional<CpeMatch> own = config.nodes().stream().filter(n -> !n.negate())
                    .flatMap(n -> n.matches().stream())
                    .filter(m -> m.vulnerable() && applies(m, vendorProduct, v))
                    .findFirst();
            if (own.isEmpty()) {
                continue;
            }
            if (evaluate(config, vendorProduct, v, context)) {
                return own;
            }
        }
        return Optional.empty();
    }

    /** 단순 판정: 조건 목록 중 하나라도 제품·버전에 해당하는지 (AND 문맥 없이). */
    public static Optional<CpeMatch> match(List<CpeMatch> matches, String vendorProduct, String version) {
        String v = cpeVersion(version);
        return matches.stream().filter(m -> applies(m, vendorProduct, v)).findFirst();
    }

    private static boolean evaluate(Config config, String vendorProduct, String version, Map<String, Set<String>> context) {
        List<Boolean> results = new ArrayList<>();
        for (Node node : config.nodes()) {
            results.add(evaluate(node, vendorProduct, version, context));
        }
        return "AND".equalsIgnoreCase(config.operator())
                ? results.stream().allMatch(b -> b)
                : results.stream().anyMatch(b -> b);
    }

    private static boolean evaluate(Node node, String vendorProduct, String version, Map<String, Set<String>> context) {
        List<Boolean> results = new ArrayList<>();
        for (CpeMatch m : node.matches()) {
            results.add(satisfied(m, vendorProduct, version, context));
        }
        boolean r = "AND".equalsIgnoreCase(node.operator())
                ? !results.isEmpty() && results.stream().allMatch(b -> b)
                : results.stream().anyMatch(b -> b);
        return node.negate() != r;
    }

    /** 조건 하나가 지금 환경에서 성립하는지. 대상 제품이면 그 버전으로, 다른 제품이면 클래스패스의 버전으로 본다. */
    private static boolean satisfied(CpeMatch m, String vendorProduct, String version, Map<String, Set<String>> context) {
        String[] f = split(m.criteria());
        if (f.length < 11) {
            return false;
        }
        String vp = f[3] + ":" + f[4];
        if (vp.equals(vendorProduct)) {
            return applies(m, vendorProduct, version);
        }
        Set<String> versions = context.getOrDefault(vp, Set.of());
        return versions.stream().anyMatch(other -> applies(m, vp, cpeVersion(other)));
    }

    static boolean applies(CpeMatch m, String vendorProduct, String version) {
        String[] f = split(m.criteria());
        if (f.length < 11 || !"a".equals(f[2])) {
            return false;
        }
        if (!(f[3] + ":" + f[4]).equals(vendorProduct)) {
            return false;
        }
        if (!JAVA_TARGETS.contains(f[10].toLowerCase())) {
            return false;
        }
        String exact = f[5];
        if (exact.equals("-")) {
            return false;  // NA: 특정 버전 체계에 속하지 않는 배포판 패키지 등
        }
        if (!exact.equals("*")) {
            // 정확한 버전 조건. update 필드(alpha 등)가 있으면 버전에 붙여 비교한다
            String full = f[6].equals("*") || f[6].equals("-") ? exact : exact + "-" + f[6];
            return Versions.compare(full, version) == 0;
        }
        return inRange(m, version);
    }

    /** 범위 필드만으로 판정 (조건의 버전 필드가 "*"일 때). 범위 필드가 하나도 없으면 모든 버전이다. */
    public static boolean inRange(CpeMatch m, String version) {
        if (m.versionStartIncluding() != null && Versions.compare(version, m.versionStartIncluding()) < 0) {
            return false;
        }
        if (m.versionStartExcluding() != null && Versions.compare(version, m.versionStartExcluding()) <= 0) {
            return false;
        }
        if (m.versionEndIncluding() != null && Versions.compare(version, m.versionEndIncluding()) > 0) {
            return false;
        }
        return m.versionEndExcluding() == null || Versions.compare(version, m.versionEndExcluding()) < 0;
    }

    /**
     * NVD는 변형 꼬리표 없이 버전을 적는다(guava "32.0.0", netty "4.1.138"). Maven 비교에서 "33.7.2-jre"는
     * "33.7.2"보다 크게 정렬되므로, 비교 전에 꼬리표를 뗀다. Final·RELEASE는 Maven 규칙상 정식 버전과 같아 그대로 둔다.
     */
    static String cpeVersion(String version) {
        String flavor = PublishedVersions.flavor(version);
        return flavor.isEmpty() ? version : version.substring(0, version.length() - flavor.length() - 1);
    }

    /** CPE는 "\:"로 콜론을 이스케이프할 수 있어 단순 split을 쓰지 않는다. "mysql_connector\/j"의 "\/"는 그대로 둔다. */
    static String[] split(String cpe) {
        List<String> out = new ArrayList<>();
        StringBuilder cur = new StringBuilder();
        for (int i = 0; i < cpe.length(); i++) {
            char ch = cpe.charAt(i);
            if (ch == '\\' && i + 1 < cpe.length()) {
                cur.append(ch).append(cpe.charAt(++i));
            } else if (ch == ':') {
                out.add(cur.toString());
                cur.setLength(0);
            } else {
                cur.append(ch);
            }
        }
        out.add(cur.toString());
        return out.toArray(String[]::new);
    }
}
