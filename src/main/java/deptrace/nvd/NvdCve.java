package deptrace.nvd;

import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.databind.JsonNode;

import deptrace.osv.Severity;

/**
 * NVD CVE API 2.0 응답에서 판정에 필요한 부분만 읽은 것.
 *
 * <p>NVD의 적용 조건(configurations)은 논리식이다. 설정(configuration) 안의 노드(node)를 AND/OR로 묶고,
 * 노드 안의 CPE 조건(cpeMatch)도 AND/OR로 묶는다. vulnerable=false인 조건은 "이 환경에서 실행될 때"라는 플랫폼 조건이다.
 * 예: CVE-2018-1258은 "Spring Security(모든 버전) AND Spring Framework 5.0.5"라서, Spring Security만 보고 판정하면 틀린다.
 */
public record NvdCve(String id, String published, String status, Severity severity, String summary, List<Config> configs) {

    /** operator가 null이면 OR로 본다. */
    public record Config(String operator, List<Node> nodes) {
    }

    public record Node(String operator, boolean negate, List<CpeMatch> matches) {
    }

    /** cpeMatch 하나. 범위 필드는 없으면 null. */
    public record CpeMatch(String criteria, boolean vulnerable, String versionStartIncluding, String versionStartExcluding,
                           String versionEndIncluding, String versionEndExcluding) {

        /** 테스트·간단한 데이터용: 취약 조건 하나. */
        public static CpeMatch vulnerable(String criteria, String startIncl, String endExcl) {
            return new CpeMatch(criteria, true, startIncl, null, null, endExcl);
        }
    }

    /** 노드 하나(OR)에 취약 조건들만 담은 간단한 CVE. 테스트용. */
    public static NvdCve simple(String id, Severity severity, CpeMatch... matches) {
        return new NvdCve(id, "", "Analyzed", severity, "",
                List.of(new Config(null, List.of(new Node("OR", false, List.of(matches))))));
    }

    public static NvdCve from(JsonNode cve) {
        List<Config> configs = new ArrayList<>();
        for (JsonNode config : cve.path("configurations")) {
            List<Node> nodes = new ArrayList<>();
            for (JsonNode node : config.path("nodes")) {
                List<CpeMatch> matches = new ArrayList<>();
                for (JsonNode m : node.path("cpeMatch")) {
                    matches.add(new CpeMatch(m.path("criteria").asText(), m.path("vulnerable").asBoolean(false),
                            text(m, "versionStartIncluding"), text(m, "versionStartExcluding"),
                            text(m, "versionEndIncluding"), text(m, "versionEndExcluding")));
                }
                nodes.add(new Node(text(node, "operator"), node.path("negate").asBoolean(false), List.copyOf(matches)));
            }
            configs.add(new Config(text(config, "operator"), List.copyOf(nodes)));
        }
        String summary = "";
        for (JsonNode d : cve.path("descriptions")) {
            if ("en".equals(d.path("lang").asText())) {
                summary = d.path("value").asText();
                break;
            }
        }
        return new NvdCve(cve.path("id").asText(), cve.path("published").asText(), cve.path("vulnStatus").asText(),
                severity(cve.path("metrics")), summary.length() > 200 ? summary.substring(0, 200) + "…" : summary,
                List.copyOf(configs));
    }

    /** CVSS v4.0 → v3.1 → v3.0 → v2 순으로 처음 나오는 기본 심각도. */
    private static Severity severity(JsonNode metrics) {
        for (String key : List.of("cvssMetricV40", "cvssMetricV31", "cvssMetricV30")) {
            for (JsonNode m : metrics.path(key)) {
                String s = m.path("cvssData").path("baseSeverity").asText(null);
                if (s != null) {
                    return Severity.parse(s);
                }
            }
        }
        for (JsonNode m : metrics.path("cvssMetricV2")) {
            String s = m.path("baseSeverity").asText(null);
            if (s != null) {
                return Severity.parse(s);
            }
        }
        return Severity.UNKNOWN;
    }

    private static String text(JsonNode n, String field) {
        JsonNode v = n.get(field);
        return v == null || v.isNull() ? null : v.asText();
    }
}
