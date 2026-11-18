package deptrace.license;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Path;
import java.time.LocalDate;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;

import deptrace.license.LicenseResolver.ComponentLicense;

/**
 * 라이선스 정책. 분류 단위로 막을 것(deny)과 사람이 볼 것(review)을 정하고, 필요하면 SPDX 식별자 단위로 덮어쓴다.
 *
 * <pre>
 * deny: [STRONG_COPYLEFT, NETWORK_COPYLEFT]
 * review: [WEAK_COPYLEFT, UNKNOWN]
 * allowLicenses: [GPL-2.0-only WITH Classpath-exception-2.0]   # 분류와 무관하게 허용
 * denyLicenses: []                                             # 분류와 무관하게 금지
 * exceptions:
 *   - package: org.example:lib
 *     reason: 빌드 도구로만 쓰고 배포물에 포함되지 않음 (bootJar 확인)
 *     expires: 2027-01-19
 * </pre>
 *
 * <p>다중 라이선스는 OR로 보므로, 금지되지 않은 선택지가 하나라도 있으면 위반이 아니다.
 * 예외는 취약점 예외와 같은 원칙(ADR 0003)으로 사유와 만료일이 있어야 인정한다.
 */
public record LicensePolicy(List<LicenseCategory> deny, List<LicenseCategory> review,
                            List<String> allowLicenses, List<String> denyLicenses,
                            List<LicenseException> exceptions) {

    public record LicenseException(@JsonProperty("package") String packageName, String reason, String expires) {
    }

    public static final LicensePolicy DEFAULT = new LicensePolicy(
            List.of(LicenseCategory.STRONG_COPYLEFT, LicenseCategory.NETWORK_COPYLEFT),
            List.of(LicenseCategory.WEAK_COPYLEFT, LicenseCategory.UNKNOWN),
            List.of(), List.of(), List.of());

    public LicensePolicy {
        deny = deny == null ? List.of() : List.copyOf(deny);
        review = review == null ? List.of() : List.copyOf(review);
        allowLicenses = allowLicenses == null ? List.of() : List.copyOf(allowLicenses);
        denyLicenses = denyLicenses == null ? List.of() : List.copyOf(denyLicenses);
        exceptions = exceptions == null ? List.of() : List.copyOf(exceptions);
    }

    public static LicensePolicy load(Path file) {
        if (file == null) {
            return DEFAULT;
        }
        try {
            ObjectMapper yaml = new ObjectMapper(new YAMLFactory())
                    .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
            LicensePolicy p = yaml.readValue(file.toFile(), LicensePolicy.class);
            return p == null ? DEFAULT : p;
        } catch (IOException e) {
            throw new UncheckedIOException("라이선스 정책 파일을 읽을 수 없습니다: " + file, e);
        }
    }

    public enum Verdict { ALLOWED, REVIEW, DENIED, ACCEPTED }

    /** chosen: 허용 판단에 쓴 선택지(OR 중 하나). 없으면 null. */
    public record Decision(ComponentLicense license, Verdict verdict, String chosen, String note) {
    }

    public record Result(List<Decision> decisions, List<String> problems) {

        public List<Decision> with(Verdict v) {
            return decisions.stream().filter(d -> d.verdict() == v).toList();
        }

        public boolean passed() {
            return with(Verdict.DENIED).isEmpty() && problems.isEmpty();
        }
    }

    public Result evaluate(List<ComponentLicense> licenses, LocalDate today) {
        List<String> problems = new ArrayList<>();
        for (LicenseException e : exceptions) {
            if (isBlank(e.packageName()) || isBlank(e.reason()) || isBlank(e.expires())) {
                problems.add("예외 항목에 package·reason·expires가 모두 필요합니다: " + e);
            } else if (parse(e.expires()) == null) {
                problems.add("expires 날짜 형식(YYYY-MM-DD)이 아닙니다: " + e);
            }
        }
        for (String id : concat(allowLicenses, denyLicenses)) {
            if (SpdxCatalog.byId(id).isEmpty()) {
                problems.add("알 수 없는 라이선스 식별자입니다: " + id);
            }
        }

        List<Decision> decisions = new ArrayList<>();
        for (ComponentLicense l : licenses) {
            Decision d = decide(l);
            if (d.verdict() == Verdict.DENIED) {
                d = applyException(d, today);
            }
            decisions.add(d);
        }
        return new Result(decisions, problems);
    }

    private Decision decide(ComponentLicense l) {
        // OR 선택지 중 명시적으로 허용된 것이 있으면 그것을 고른다
        for (String id : l.spdx()) {
            if (allowLicenses.contains(id)) {
                return new Decision(l, Verdict.ALLOWED, id, "정책에서 허용한 라이선스");
            }
        }
        // 금지되지 않은 선택지 중 가장 제약이 적은 것
        Optional<SpdxCatalog.License> best = l.spdx().stream()
                .map(SpdxCatalog::byId).flatMap(Optional::stream)
                .filter(x -> !denyLicenses.contains(x.id()) && !deny.contains(x.category()))
                .min(Comparator.comparing(SpdxCatalog.License::category));
        if (best.isPresent()) {
            SpdxCatalog.License chosen = best.get();
            boolean needsReview = review.contains(chosen.category());
            String note = l.multiple() && l.spdx().size() > 1 ? "다중 라이선스 중 " + chosen.id() + " 선택 가정" : "";
            return new Decision(l, needsReview ? Verdict.REVIEW : Verdict.ALLOWED, chosen.id(), note);
        }
        if (l.spdx().isEmpty()) {
            // 식별하지 못함: UNKNOWN 분류로 판단
            Verdict v = deny.contains(LicenseCategory.UNKNOWN) ? Verdict.DENIED
                    : review.contains(LicenseCategory.UNKNOWN) ? Verdict.REVIEW : Verdict.ALLOWED;
            return new Decision(l, v, null, unknownNote(l));
        }
        return new Decision(l, Verdict.DENIED, null, "모든 선택지가 금지됨: " + l.expression());
    }

    private Decision applyException(Decision d, LocalDate today) {
        Optional<LicenseException> match = exceptions.stream()
                .filter(e -> !isBlank(e.reason()) && d.license().module().equals(e.packageName()))
                .findFirst();
        if (match.isEmpty()) {
            return d;
        }
        LocalDate expires = parse(match.get().expires());
        if (expires == null || expires.isBefore(today)) {
            return new Decision(d.license(), Verdict.DENIED, null, "예외가 " + match.get().expires() + "에 만료됨: " + match.get().reason());
        }
        return new Decision(d.license(), Verdict.ACCEPTED, null, match.get().reason() + " (만료 " + match.get().expires() + ")");
    }

    private static String unknownNote(ComponentLicense l) {
        return switch (l.status()) {
            case POM_UNAVAILABLE -> "POM을 받지 못함";
            case NOT_DECLARED -> "POM과 부모 POM에 라이선스 선언 없음";
            default -> "식별하지 못한 선언: " + String.join(", ", l.unmatched());
        };
    }

    private static List<String> concat(List<String> a, List<String> b) {
        List<String> out = new ArrayList<>(a);
        out.addAll(b);
        return out;
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
