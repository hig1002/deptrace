package deptrace.sbom;

import java.time.LocalDate;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import deptrace.analysis.AnalysisResult;
import deptrace.analysis.AnalysisResult.Advisory;
import deptrace.analysis.AnalysisResult.Finding;
import deptrace.graph.GraphExport;
import deptrace.graph.ResolvedGraph;
import deptrace.license.LicenseResolver.ComponentLicense;
import deptrace.model.Coordinate;
import deptrace.policy.PolicyGate;
import deptrace.policy.PolicyGate.PolicyException;

/**
 * 해석 그래프를 CycloneDX 1.6 JSON SBOM으로 쓴다.
 *
 * <ul>
 *   <li>components: 배포 클래스패스의 구성요소. bom-ref는 purl.</li>
 *   <li>licenses: POM에서 판정한 라이선스. 단일 SPDX 식별자는 license.id, 복합(OR·WITH·LicenseRef)은 expression,
 *       식별하지 못한 것은 원문을 license.name으로 둔다. 모르는 것을 SPDX로 추측해 적지 않는다.</li>
 *   <li>dependencies: 실제 유입 엣지만. BOM/platform 제약 엣지는 구성요소를 끌어오지 않으므로 넣지 않는다.</li>
 *   <li>vulnerabilities(선택): analyze 결과와 예외 파일로 VEX 분석 상태를 붙인다.
 *       유효한 예외는 not_affected, 나머지는 in_triage. "취약하다"(exploitable)는 확인하지 않은 것을 단정하지 않는다.</li>
 * </ul>
 */
public final class CycloneDxWriter {

    public static final String SPEC_VERSION = "1.6";

    private static final ObjectMapper MAPPER = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

    private CycloneDxWriter() {
    }

    /**
     * @param licenses   구성요소별 라이선스 (없으면 빈 목록: licenses 필드를 생략)
     * @param analysis   analyze 결과 (없으면 null: vulnerabilities 생략)
     * @param exceptions 취약점 예외
     */
    public static ObjectNode write(ResolvedGraph graph, List<ComponentLicense> licenses, AnalysisResult analysis,
                                   List<PolicyException> exceptions, LocalDate today, String toolVersion) {
        ObjectNode bom = MAPPER.createObjectNode();
        bom.put("bomFormat", "CycloneDX");
        bom.put("specVersion", SPEC_VERSION);
        bom.put("serialNumber", "urn:uuid:" + UUID.randomUUID());
        bom.put("version", 1);

        String rootRef = rootRef(graph.data());
        bom.set("metadata", metadata(graph, rootRef, toolVersion));

        Map<String, ComponentLicense> licenseOf = new LinkedHashMap<>();
        licenses.forEach(l -> licenseOf.put(l.coordinate(), l));

        List<ResolvedGraph.Node> nodes = graph.components().stream()
                .sorted(Comparator.comparing(n -> n.coordinate().purl())).toList();
        ArrayNode components = bom.putArray("components");
        for (ResolvedGraph.Node n : nodes) {
            components.add(component(n, licenseOf.get(n.coordinate().toString())));
        }

        bom.set("dependencies", dependencies(graph, rootRef, nodes));

        if (analysis != null) {
            ArrayNode vulns = vulnerabilities(analysis, exceptions, today);
            if (!vulns.isEmpty()) {
                bom.set("vulnerabilities", vulns);
            }
        }
        return bom;
    }

    public static String toJson(ObjectNode bom) {
        try {
            return MAPPER.writeValueAsString(bom);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static ObjectNode metadata(ResolvedGraph graph, String rootRef, String toolVersion) {
        ObjectNode m = MAPPER.createObjectNode();
        m.put("timestamp", OffsetDateTime.now(ZoneId.of("UTC")).truncatedTo(ChronoUnit.SECONDS).toString());
        // 해석 결과에서 만든 SBOM이므로 build 단계 산출물이다
        m.putArray("lifecycles").addObject().put("phase", "build");
        ObjectNode tool = m.putObject("tools").putArray("components").addObject();
        tool.put("type", "application");
        tool.put("name", "deptrace");
        tool.put("version", toolVersion);

        GraphExport d = graph.data();
        ObjectNode root = m.putObject("component");
        root.put("type", "application");
        root.put("bom-ref", rootRef);
        if (present(d.projectGroup())) {
            root.put("group", d.projectGroup());
        }
        root.put("name", present(d.projectName()) ? d.projectName() : graph.project());
        if (present(d.projectVersion())) {
            root.put("version", d.projectVersion());
        }
        ArrayNode props = m.putArray("properties");
        property(props, "deptrace:configuration", graph.configuration());
        property(props, "deptrace:gradleVersion", d.gradleVersion());
        return m;
    }

    private static ObjectNode component(ResolvedGraph.Node n, ComponentLicense license) {
        Coordinate c = n.coordinate();
        ObjectNode o = MAPPER.createObjectNode();
        o.put("type", "library");
        o.put("bom-ref", c.purl());
        o.put("group", c.group());
        o.put("name", c.artifact());
        o.put("version", c.version());
        o.put("scope", "required");
        o.put("purl", c.purl());
        if (license != null) {
            ArrayNode ls = licenses(license);
            if (!ls.isEmpty()) {
                o.set("licenses", ls);
            }
        }
        ArrayNode props = o.putArray("properties");
        // 버전이 왜 선택됐는지는 SBOM 표준 필드에 없어 속성으로 남긴다 (DepTrace의 핵심 정보)
        property(props, "deptrace:selectionReason", String.join(",", n.causes()));
        if (license != null && license.declaredIn() != null && !license.declaredIn().equals(license.coordinate())) {
            property(props, "deptrace:licenseInheritedFrom", license.declaredIn());
        }
        return o;
    }

    /** CycloneDX: licenses는 license 객체들의 배열이거나, expression 하나만 담은 배열이어야 한다(둘을 섞을 수 없다). */
    static ArrayNode licenses(ComponentLicense l) {
        ArrayNode arr = MAPPER.createArrayNode();
        if (l.spdx().size() == 1 && isPlainSpdxId(l.spdx().get(0)) && l.unmatched().isEmpty()) {
            arr.addObject().putObject("license").put("id", l.spdx().get(0));
        } else if (!l.spdx().isEmpty() && l.unmatched().isEmpty()) {
            arr.addObject().put("expression", l.spdx().size() == 1 ? l.spdx().get(0) : l.expression());
        } else {
            // 일부라도 식별하지 못했으면 식별한 것과 원문을 모두 license 객체로 남긴다
            for (String id : l.spdx()) {
                if (isPlainSpdxId(id)) {
                    arr.addObject().putObject("license").put("id", id);
                } else {
                    arr.addObject().putObject("license").put("name", id);
                }
            }
            for (String raw : l.unmatched()) {
                arr.addObject().putObject("license").put("name", raw);
            }
        }
        return arr;
    }

    /** license.id에는 SPDX 목록의 단일 식별자만 들어간다. WITH 예외 조항·LicenseRef는 expression으로 쓴다. */
    private static boolean isPlainSpdxId(String id) {
        return !id.contains(" ") && !id.startsWith("LicenseRef-");
    }

    private static ArrayNode dependencies(ResolvedGraph graph, String rootRef, List<ResolvedGraph.Node> nodes) {
        ArrayNode deps = MAPPER.createArrayNode();
        deps.add(dependency(rootRef, graph.directDependencyIds(), graph));
        for (ResolvedGraph.Node n : nodes) {
            List<String> to = graph.dependencyEdgesFrom(n.id()).stream().map(ResolvedGraph.Edge::to).toList();
            deps.add(dependency(n.coordinate().purl(), to, graph));
        }
        return deps;
    }

    private static ObjectNode dependency(String ref, List<String> targetIds, ResolvedGraph graph) {
        ObjectNode o = MAPPER.createObjectNode();
        o.put("ref", ref);
        Set<String> refs = new LinkedHashSet<>();
        for (String id : targetIds) {
            graph.node(id).filter(ResolvedGraph.Node::isComponent).ifPresent(t -> refs.add(t.coordinate().purl()));
        }
        ArrayNode on = o.putArray("dependsOn");
        refs.stream().sorted().forEach(on::add);
        return o;
    }

    private static ArrayNode vulnerabilities(AnalysisResult analysis, List<PolicyException> exceptions, LocalDate today) {
        // 같은 권고가 여러 구성요소에 걸리면 vulnerability 하나에 affects를 여러 개 둔다
        Map<String, ObjectNode> byId = new LinkedHashMap<>();
        Map<String, List<String>> notAffectedDetail = new LinkedHashMap<>();
        Map<String, Boolean> allExcepted = new LinkedHashMap<>();
        for (Finding f : analysis.findings()) {
            if (!f.inPrimary()) {
                continue;
            }
            String purl = Coordinate.parse(f.coordinate()).map(Coordinate::purl).orElse(null);
            if (purl == null) {
                continue;
            }
            for (Advisory a : f.advisories()) {
                ObjectNode v = byId.computeIfAbsent(a.id(), id -> vulnerability(a, f));
                ((ArrayNode) v.get("affects")).addObject().put("ref", purl);

                Optional<PolicyException> ex = PolicyGate.exceptionFor(exceptions, f, a);
                boolean active = ex.isPresent() && PolicyGate.isActive(ex.get(), today);
                allExcepted.merge(a.id(), active, Boolean::logicalAnd);
                if (active) {
                    notAffectedDetail.computeIfAbsent(a.id(), k -> new ArrayList<>())
                            .add(f.module() + ": " + ex.get().reason() + " (재검토 " + ex.get().expires() + ")");
                }
            }
        }
        ArrayNode out = MAPPER.createArrayNode();
        byId.forEach((id, v) -> {
            ObjectNode analysisNode = v.putObject("analysis");
            if (allExcepted.getOrDefault(id, false)) {
                // 예외 근거는 "해당 기능을 쓰지 않는다"(코드 검색)이므로 취약 코드에 도달하지 않는다로 둔다
                analysisNode.put("state", "not_affected");
                analysisNode.put("justification", "code_not_reachable");
                analysisNode.put("detail", String.join("\n", notAffectedDetail.get(id)));
            } else {
                analysisNode.put("state", "in_triage");
            }
            out.add(v);
        });
        return out;
    }

    private static ObjectNode vulnerability(Advisory a, Finding f) {
        ObjectNode v = MAPPER.createObjectNode();
        v.put("bom-ref", "vuln:" + a.id());
        v.put("id", a.id());
        ObjectNode source = v.putObject("source");
        source.put("name", "OSV");
        source.put("url", "https://osv.dev/vulnerability/" + a.id());
        ArrayNode refs = v.putArray("references");
        for (String alias : a.aliases()) {
            if (!alias.equals(a.id())) {
                ObjectNode r = refs.addObject();
                r.put("id", alias);
                r.putObject("source").put("name", alias.startsWith("CVE-") ? "NVD" : "OSV")
                        .put("url", alias.startsWith("CVE-") ? "https://nvd.nist.gov/vuln/detail/" + alias : "https://osv.dev/vulnerability/" + alias);
            }
        }
        if (refs.isEmpty()) {
            v.remove("references");
        }
        ObjectNode rating = v.putArray("ratings").addObject();
        rating.putObject("source").put("name", "OSV");
        rating.put("severity", severity(a.severity()));
        if (a.summary() != null) {
            v.put("description", a.summary());
        }
        if (f.remediationAdvice() != null) {
            v.put("recommendation", f.remediationAdvice());
        }
        v.putArray("affects");
        return v;
    }

    /** CycloneDX 심각도: critical, high, medium, low, info, none, unknown. OSV의 MODERATE는 medium. */
    static String severity(String osv) {
        return switch (osv) {
            case "CRITICAL" -> "critical";
            case "HIGH" -> "high";
            case "MODERATE" -> "medium";
            case "LOW" -> "low";
            default -> "unknown";
        };
    }

    private static String rootRef(GraphExport d) {
        if (present(d.projectGroup()) && present(d.projectName()) && present(d.projectVersion())) {
            return new Coordinate(d.projectGroup(), d.projectName(), d.projectVersion()).purl();
        }
        return "deptrace:root";
    }

    private static void property(ArrayNode props, String name, String value) {
        if (present(value)) {
            props.addObject().put("name", name).put("value", value);
        }
    }

    private static boolean present(String s) {
        return s != null && !s.isBlank() && !s.equals("unspecified");
    }
}
