package deptrace.osv;

import java.util.Comparator;

/** GitHub Advisory Database가 OSV의 database_specific.severity에 기록하는 등급. */
public enum Severity {
    UNKNOWN, LOW, MODERATE, HIGH, CRITICAL;

    /** 등급 이름 문자열을 높은 등급부터 정렬 (요약 표 출력용). */
    public static final Comparator<String> NAME_DESCENDING = Comparator.comparing(Severity::parse).reversed();

    public static Severity parse(String value) {
        if (value == null || value.isBlank()) {
            return UNKNOWN;
        }
        String v = value.trim().toUpperCase();
        if (v.equals("MEDIUM")) {
            return MODERATE;
        }
        try {
            return Severity.valueOf(v);
        } catch (IllegalArgumentException e) {
            return UNKNOWN;
        }
    }

    public boolean atLeast(Severity other) {
        return compareTo(other) >= 0;
    }
}
