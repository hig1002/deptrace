package deptrace.license;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

import deptrace.license.Pom.DeclaredLicense;

/**
 * POM에 자유 형식으로 적힌 라이선스 이름·URL을 SPDX 식별자로 정규화한다.
 *
 * <p>같은 Apache-2.0도 "The Apache Software License, Version 2.0", "Apache 2", "ASL 2.0"처럼 제각각 적힌다.
 * URL이 이름보다 일관적이라 URL을 먼저 보고, 그다음 정규화한 이름을 본다.
 * 식별하지 못한 값은 추측하지 않고 UNKNOWN으로 남겨 사람이 확인하게 한다.
 */
public final class SpdxCatalog {

    /** SPDX 식별자(또는 LicenseRef-*)와 분류. */
    public record License(String id, LicenseCategory category) {
    }

    private record Entry(License license, List<String> names, List<String> urls) {
    }

    private static final List<Entry> ENTRIES = new ArrayList<>();
    private static final Map<String, License> BY_ID = new LinkedHashMap<>();

    static {
        LicenseCategory P = LicenseCategory.PERMISSIVE;
        LicenseCategory W = LicenseCategory.WEAK_COPYLEFT;
        LicenseCategory S = LicenseCategory.STRONG_COPYLEFT;
        LicenseCategory N = LicenseCategory.NETWORK_COPYLEFT;

        add("Apache-2.0", P,
                List.of("apache license version 2.0", "apache license 2.0", "apache 2.0", "apache 2", "apache-2.0", "apache2",
                        "the apache software license version 2.0", "apache software license version 2.0",
                        "apache software license - version 2.0", "the apache license version 2.0", "asl 2.0", "al 2.0",
                        "apache license v2.0", "apache license v2", "apache public license 2.0"),
                List.of("apache.org/licenses/license-2.0", "opensource.org/licenses/apache-2.0", "spdx.org/licenses/apache-2.0"));
        add("MIT", P,
                List.of("mit", "mit license", "the mit license", "mit-license", "the mit license (mit)", "bouncy castle licence",
                        "bouncy castle license"),
                List.of("opensource.org/licenses/mit", "spdx.org/licenses/mit", "bouncycastle.org/licence", "mit-license.org"));
        // MIT-0은 고지 의무도 없는 별개 라이선스. URL이 MIT의 URL을 포함하므로 더 긴 URL 우선 규칙으로 구분된다
        add("MIT-0", P, List.of("mit-0", "mit no attribution", "mit-0 license"),
                List.of("opensource.org/licenses/mit-0", "spdx.org/licenses/mit-0", "github.com/aws/mit-0"));
        add("BSD-3-Clause", P,
                List.of("bsd 3-clause", "bsd-3-clause", "new bsd license", "the new bsd license", "revised bsd license",
                        "bsd 3-clause license", "the bsd 3-clause license", "3-clause bsd license", "modified bsd license",
                        "eclipse distribution license - v 1.0", "eclipse distribution license v. 1.0", "edl 1.0", "go license"),
                List.of("opensource.org/licenses/bsd-3-clause", "spdx.org/licenses/bsd-3-clause", "eclipse.org/org/documents/edl-v10",
                        "golang.org/license"));
        add("BSD-2-Clause", P,
                List.of("bsd 2-clause", "bsd-2-clause", "simplified bsd license", "the bsd 2-clause license", "freebsd license"),
                List.of("opensource.org/licenses/bsd-2-clause", "spdx.org/licenses/bsd-2-clause"));
        // 조항 수가 적히지 않은 BSD. 2·3조항 모두 허용형이라 분류는 같지만, 식별자는 추측하지 않는다
        add("LicenseRef-BSD", P, List.of("bsd", "bsd license", "the bsd license", "bsd style", "bsd-style license"),
                List.of("opensource.org/licenses/bsd-license"));
        add("ISC", P, List.of("isc", "isc license"), List.of("opensource.org/licenses/isc"));
        add("0BSD", P, List.of("0bsd", "zero-clause bsd"), List.of("opensource.org/licenses/0bsd"));
        add("Unlicense", P, List.of("unlicense", "the unlicense"), List.of("unlicense.org"));
        add("CC0-1.0", P,
                List.of("cc0", "cc0 1.0", "cc0-1.0", "cc0 1.0 universal", "public domain, per creative commons cc0",
                        "creative commons zero"),
                List.of("creativecommons.org/publicdomain/zero/1.0"));
        add("LicenseRef-Public-Domain", P, List.of("public domain"), List.of());
        add("Unicode-3.0", P, List.of("unicode/icu license", "unicode license", "icu license", "unicode-3.0"),
                List.of("unicode.org/copyright", "unicode.org/license"));
        add("EPL-1.0", W,
                List.of("eclipse public license - v 1.0", "eclipse public license 1.0", "eclipse public license v1.0", "epl 1.0",
                        "epl-1.0", "eclipse public license - version 1.0"),
                List.of("eclipse.org/legal/epl-v10", "opensource.org/licenses/epl-1.0", "spdx.org/licenses/epl-1.0"));
        add("EPL-2.0", W,
                List.of("eclipse public license - v 2.0", "eclipse public license 2.0", "eclipse public license v2.0", "epl 2.0",
                        "epl-2.0", "eclipse public license - version 2.0"),
                List.of("eclipse.org/legal/epl-2.0", "eclipse.org/legal/epl-v20", "opensource.org/licenses/epl-2.0",
                        "spdx.org/licenses/epl-2.0"));
        add("LGPL-2.1-only", W,
                List.of("gnu lesser general public license version 2.1", "lgpl 2.1", "lgpl-2.1", "lgpl v2.1", "lgplv2.1",
                        "gnu lesser general public license v2.1", "gnu lgpl 2.1", "gnu lesser general public license"),
                List.of("gnu.org/licenses/old-licenses/lgpl-2.1", "opensource.org/licenses/lgpl-2.1"));
        // "or later"는 이름에만 드러나고 URL은 2.1과 같다. 이름을 URL보다 먼저 보는 이유 중 하나
        add("LGPL-2.1-or-later", W,
                List.of("gnu library general public license v2.1 or later", "gnu lesser general public license v2.1 or later",
                        "lgpl-2.1-or-later", "lgpl 2.1 or later", "lgpl-2.1+", "lgpl v2.1 or later"),
                List.of());
        add("LGPL-3.0-only", W,
                List.of("gnu lesser general public license version 3", "lgpl 3.0", "lgpl-3.0", "lgplv3", "gnu lesser general public license v3.0"),
                List.of("gnu.org/licenses/lgpl", "opensource.org/licenses/lgpl-3.0"));
        add("MPL-2.0", W, List.of("mozilla public license version 2.0", "mozilla public license 2.0", "mpl 2.0", "mpl-2.0"),
                List.of("mozilla.org/mpl/2.0", "opensource.org/licenses/mpl-2.0"));
        add("MPL-1.1", W, List.of("mozilla public license version 1.1", "mpl 1.1", "mpl-1.1"), List.of("mozilla.org/mpl/mpl-1.1"));
        add("CDDL-1.0", W, List.of("cddl", "cddl 1.0", "common development and distribution license",
                        "common development and distribution license (cddl) v1.0"),
                List.of("opensource.org/licenses/cddl1"));
        add("CDDL-1.1", W, List.of("cddl 1.1", "cddl-1.1", "common development and distribution license 1.1"),
                List.of("glassfish.dev.java.net/public/cddl+gpl_1_1", "oss.oracle.com/licenses/cddl+gpl-1.1"));
        add("CPL-1.0", W, List.of("common public license version 1.0", "cpl 1.0", "common public license"),
                List.of("opensource.org/licenses/cpl1.0", "eclipse.org/legal/cpl-v10"));
        // Classpath 예외: 라이브러리로 링크만 하면 결합 저작물에 GPL이 전파되지 않는다
        add("GPL-2.0-only WITH Classpath-exception-2.0", W,
                List.of("gpl2 w/ cpe", "gplv2+ce", "gnu general public license version 2 with the classpath exception",
                        "gpl-2.0-with-classpath-exception", "gnu general public license, version 2 with the classpath exception",
                        "gpl 2 with classpath exception"),
                List.of("openjdk.java.net/legal/gplv2+ce", "openjdk.org/legal/gplv2+ce", "gnu.org/software/classpath/license"));
        // 버전 없는 "CDDL + GPLv2 with classpath exception"은 Java EE·GlassFish 계열이 쓰는 표기다.
        // javax.annotation-api 1.3.2의 POM이 가리키는 LICENSE 원문이 CDDL 1.1임을 확인했다 (CycloneDX Gradle 플러그인은 1.0으로 표기)
        add("CDDL-1.1 OR GPL-2.0-only WITH Classpath-exception-2.0", W,
                List.of("cddl + gplv2 with classpath exception", "cddl/gplv2+ce", "cddl+gpl license", "cddl+gpl_1_1",
                        "dual license consisting of the cddl v1.1 and gpl v2"),
                List.of());
        // MySQL Connector/J. Universal FOSS 예외는 결합한 프로그램이 오픈소스 라이선스일 때만 GPL 전파를 면제한다.
        // 비공개 소스 서비스에는 예외가 적용되지 않으므로 Classpath 예외와 달리 강한 카피레프트로 분류한다
        add("GPL-2.0-only WITH Universal-FOSS-exception-1.0", S,
                List.of("gnu general public license v2 with universal foss exception v1.0",
                        "gpl-2.0-only with universal-foss-exception-1.0", "gplv2 with universal foss exception"),
                List.of("oss.oracle.com/licenses/universal-foss-exception"));
        add("GPL-2.0-only", S, List.of("gnu general public license version 2", "gpl 2.0", "gpl-2.0", "gplv2", "gpl v2",
                        "gnu general public license v2.0", "gnu gpl v2"),
                List.of("gnu.org/licenses/old-licenses/gpl-2.0", "opensource.org/licenses/gpl-2.0"));
        add("GPL-3.0-only", S, List.of("gnu general public license version 3", "gpl 3.0", "gpl-3.0", "gplv3", "gpl v3",
                        "gnu general public license v3.0", "gnu gpl v3"),
                List.of("gnu.org/licenses/gpl-3.0", "opensource.org/licenses/gpl-3.0"));
        add("LicenseRef-GPL", S, List.of("gpl", "gnu general public license", "gnu gpl"), List.of("gnu.org/licenses/gpl"));
        add("AGPL-3.0-only", N, List.of("gnu affero general public license version 3", "agpl 3.0", "agpl-3.0", "agplv3",
                        "gnu affero general public license v3.0", "affero general public license"),
                List.of("gnu.org/licenses/agpl", "opensource.org/licenses/agpl-v3"));
        add("SSPL-1.0", N, List.of("server side public license", "sspl", "sspl-1.0", "server side public license, v 1"),
                List.of("mongodb.com/licensing/server-side-public-license"));
    }

    private SpdxCatalog() {
    }

    private static void add(String id, LicenseCategory category, List<String> names, List<String> urls) {
        License license = new License(id, category);
        ENTRIES.add(new Entry(license, names.stream().map(SpdxCatalog::normalizeName).toList(),
                urls.stream().map(u -> u.toLowerCase(Locale.ROOT)).toList()));
        BY_ID.put(id, license);
    }

    /** SPDX 식별자로 찾는다 (정책 파일의 allow/deny 검증용). */
    public static Optional<License> byId(String id) {
        return Optional.ofNullable(BY_ID.get(id));
    }

    /**
     * POM 선언 하나를 식별한다. URL을 먼저 보고(이름보다 일관적), 그다음 이름을 본다.
     * 이름이 URL과 다른 라이선스를 가리키면 이름을 따른다: 실제로 "GPL2 w/ CPE"에 GPL 원문 URL을 다는 경우가 있어
     * URL만 보면 예외 조항을 놓친다.
     */
    public static Optional<License> identify(DeclaredLicense declared) {
        Optional<License> byName = Optional.ofNullable(declared.name()).map(SpdxCatalog::normalizeName).flatMap(SpdxCatalog::byName);
        if (byName.isPresent()) {
            return byName;
        }
        if (declared.url() != null) {
            String url = normalizeUrl(declared.url());
            // 더 긴(구체적인) URL 패턴을 우선한다: gnu.org/licenses/gpl-3.0이 gnu.org/licenses/gpl보다 먼저
            return ENTRIES.stream()
                    .flatMap(e -> e.urls().stream().filter(url::contains).map(u -> Map.entry(u.length(), e.license())))
                    .max(Map.Entry.comparingByKey())
                    .map(Map.Entry::getValue);
        }
        return Optional.empty();
    }

    private static Optional<License> byName(String normalized) {
        if (normalized.isEmpty()) {
            return Optional.empty();
        }
        // 최근 POM은 이름 자리에 SPDX 식별자를 그대로 쓰기도 한다 (logback: "LGPL-2.1-only")
        Optional<License> bySpdxId = BY_ID.values().stream()
                .filter(l -> normalizeName(l.id()).equals(normalized)).findFirst();
        if (bySpdxId.isPresent()) {
            return bySpdxId;
        }
        return ENTRIES.stream().filter(e -> e.names().contains(normalized)).map(Entry::license).findFirst();
    }

    /** 대소문자·구두점·"the"·쉼표 차이를 없앤다. "The Apache Software License, Version 2.0" → "apache software license version 2.0". */
    static String normalizeName(String name) {
        String n = name.toLowerCase(Locale.ROOT)
                .replace(',', ' ')
                .replace('(', ' ').replace(')', ' ')
                .replaceAll("\\s+", " ")
                .strip();
        if (n.startsWith("the ")) {
            n = n.substring(4);
        }
        return n;
    }

    private static String normalizeUrl(String url) {
        return url.toLowerCase(Locale.ROOT)
                .replaceFirst("^https?://", "")
                .replaceFirst("^www\\.", "")
                .strip();
    }
}
