package deptrace.license;

/**
 * 라이선스 의무의 강도. 선언 순서가 곧 제약이 큰 순서다(ordinal이 클수록 엄격).
 *
 * <p>서버에서만 실행하는 서비스는 바이너리를 배포하지 않으므로 GPL의 소스 공개 의무가 바로 발생하지는 않는다.
 * 하지만 배포 형태는 바뀔 수 있고(설치형 제공, 고객사 납품), AGPL·SSPL은 네트워크로 서비스하는 것만으로 의무가 생긴다.
 * 그래서 분류는 배포 형태와 무관하게 하고, 무엇을 막을지는 정책 파일에서 정한다.
 */
public enum LicenseCategory {

    /** 고지만 하면 되는 라이선스 (Apache-2.0, MIT, BSD, CC0 등). */
    PERMISSIVE("허용형"),
    /** 파일·라이브러리 단위 카피레프트. 수정한 그 부분만 공개 의무 (LGPL, MPL, EPL, CDDL, GPL+Classpath 예외). */
    WEAK_COPYLEFT("약한 카피레프트"),
    /** 결합한 저작물 전체에 소스 공개 의무 (GPL). */
    STRONG_COPYLEFT("강한 카피레프트"),
    /** 네트워크로 서비스만 해도 소스 공개 의무 (AGPL, SSPL). */
    NETWORK_COPYLEFT("네트워크 카피레프트"),
    /** 선언이 없거나 식별하지 못함. 사람이 확인해야 한다. */
    UNKNOWN("미확인");

    private final String label;

    LicenseCategory(String label) {
        this.label = label;
    }

    public String label() {
        return label;
    }
}
