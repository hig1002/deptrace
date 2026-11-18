package deptrace.policy;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Path;
import java.time.LocalDate;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;

import deptrace.analysis.AnalysisResult;
import deptrace.analysis.AnalysisResult.Advisory;
import deptrace.analysis.AnalysisResult.Finding;
import deptrace.osv.Severity;

/**
 * CI 게이트. 배포 클래스패스에 임계 심각도 이상의 취약점이 있으면 실패시킨다.
 *
 * <p>예외는 "왜 괜찮은지(reason)"와 "언제 다시 볼지(expires)"가 있어야만 인정한다.
 * 만료된 예외는 위반으로 되돌린다. 예외가 영구적인 무시 목록이 되는 것을 막기 위해서다.
 */
public final class PolicyGate {

    /** id는 OSV ID(GHSA)나 CVE 별칭, package는 선택(group:artifact). */
    public record PolicyException(String id, @JsonProperty("package") String packageName, String reason, String expires) {
    }

    public record ExceptionFile(List<PolicyException> exceptions) {
    }

    public record Violation(String coordinate, String advisoryId, String severity, String note) {
    }

    public record Result(List<Violation> violations, List<String> accepted, List<String> problems) {

        public boolean passed() {
            return violations.isEmpty() && problems.isEmpty();
        }
    }

    private PolicyGate() {
    }

    public static List<PolicyException> loadExceptions(Path file) {
        if (file == null) {
            return List.of();
        }
        try {
            ObjectMapper yaml = new ObjectMapper(new YAMLFactory())
                    .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
            ExceptionFile parsed = yaml.readValue(file.toFile(), ExceptionFile.class);
            return parsed == null || parsed.exceptions() == null ? List.of() : parsed.exceptions();
        } catch (IOException e) {
            throw new UncheckedIOException("예외 파일을 읽을 수 없습니다: " + file, e);
        }
    }

    public static Result evaluate(AnalysisResult result, Severity threshold, List<PolicyException> exceptions, LocalDate today) {
        List<Violation> violations = new ArrayList<>();
        List<String> accepted = new ArrayList<>();
        List<String> problems = new ArrayList<>();

        for (PolicyException e : exceptions) {
            if (isBlank(e.id()) || isBlank(e.reason()) || isBlank(e.expires())) {
                problems.add("예외 항목에 id·reason·expires가 모두 필요합니다: " + e);
            } else if (parse(e.expires()) == null) {
                problems.add("expires 날짜 형식(YYYY-MM-DD)이 아닙니다: " + e);
            }
        }

        for (Finding f : result.findings()) {
            if (!f.inPrimary()) {
                continue;
            }
            for (Advisory a : f.advisories()) {
                if (!Severity.valueOf(a.severity()).atLeast(threshold)) {
                    continue;
                }
                PolicyException match = exceptions.stream().filter(e -> matches(e, f, a)).findFirst().orElse(null);
                if (match == null) {
                    violations.add(new Violation(f.coordinate(), a.id(), a.severity(), f.remediationAdvice()));
                } else if (parse(match.expires()) != null && parse(match.expires()).isBefore(today)) {
                    violations.add(new Violation(f.coordinate(), a.id(), a.severity(),
                            "예외가 " + match.expires() + "에 만료됨: " + match.reason()));
                } else {
                    accepted.add(f.coordinate() + " " + a.id() + " — " + match.reason() + " (만료 " + match.expires() + ")");
                }
            }
        }
        return new Result(violations, accepted, problems);
    }

    public static String render(Result r, Severity threshold) {
        StringBuilder md = new StringBuilder("## DepTrace 정책 게이트: ")
                .append(r.passed() ? "통과" : "실패").append(" (기준: 배포 클래스패스, ").append(threshold).append(" 이상)\n\n");
        r.problems().forEach(p -> md.append("- 설정 오류: ").append(p).append("\n"));
        if (!r.violations().isEmpty()) {
            md.append("| 구성요소 | 권고 | 심각도 | 조치 |\n|---|---|---|---|\n");
            r.violations().forEach(v -> md.append("| ").append(v.coordinate()).append(" | ").append(v.advisoryId())
                    .append(" | ").append(v.severity()).append(" | ").append(v.note()).append(" |\n"));
        }
        if (!r.accepted().isEmpty()) {
            md.append("\n예외로 인정된 항목\n\n");
            r.accepted().forEach(a -> md.append("- ").append(a).append("\n"));
        }
        return md.toString();
    }

    /** 이 구성요소·권고에 해당하는 예외 (만료 여부는 보지 않는다). SBOM의 VEX 분석에서도 같은 기준을 쓴다. */
    public static java.util.Optional<PolicyException> exceptionFor(List<PolicyException> exceptions, Finding f, Advisory a) {
        return exceptions.stream().filter(e -> matches(e, f, a)).findFirst();
    }

    /** 만료일이 오늘 이후(오늘 포함)인 유효한 예외인지. */
    public static boolean isActive(PolicyException e, LocalDate today) {
        LocalDate expires = parse(e.expires());
        return !isBlank(e.reason()) && expires != null && !expires.isBefore(today);
    }

    private static boolean matches(PolicyException e, Finding f, Advisory a) {
        if (isBlank(e.id())) {
            return false;
        }
        boolean idMatches = e.id().equals(a.id()) || e.id().equals(a.canonicalId()) || a.aliases().contains(e.id());
        boolean packageMatches = isBlank(e.packageName()) || e.packageName().equals(f.module());
        return idMatches && packageMatches;
    }

    private static LocalDate parse(String date) {
        try {
            return date == null ? null : LocalDate.parse(date);
        } catch (DateTimeParseException ex) {
            return null;
        }
    }

    private static boolean isBlank(String s) {
        return s == null || s.isBlank();
    }
}
