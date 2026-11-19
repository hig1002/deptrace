# DepTrace

Gradle·Maven 의존성 해석 결과에 OSV 취약점 정보를 결합해, 취약한 구성요소가 **어떤 경로로 들어왔는지, 왜 그 버전이 선택됐는지, 어디를 고쳐야 하는지**를 알려주는 Java CLI입니다. CI에서 정책 게이트로도 동작합니다.

취약점 스캐너는 "무엇이 취약한가"를 알려줍니다. DepTrace는 그다음 질문에 답하려고 만들었습니다.

| 질문 | DepTrace가 보는 것 |
|---|---|
| 이 구성요소는 실제로 배포되는가? | 구성(configuration)별 해석 결과. bootJar가 쓰는 `productionRuntimeClasspath` 기준으로 판정하고 테스트 범위는 분리 |
| 왜 이 버전인가? | Gradle이 기록한 요청 버전, 선택 버전, 선택 사유(충돌 해결·BOM 규칙·제약·강제) |
| 누가 끌고 왔는가? | 직접 의존성(1차 유입자)별 최단 유입 경로 |
| 어디를 고쳐야 하는가? | 버전을 결정한 주체에 따라 직접 선언 제거·상향 / Spring Boot(BOM) 업그레이드 / constraints / 수정 불가로 분류 |
| 고친 뒤 정말 바뀌었는가? | 수정 전후 구성요소·취약점 비교(상향·하향·추가·제거, 해결·신규·잔존) |
| 라이선스 의무가 있는가? | POM(부모 상속 포함)의 선언을 SPDX로 정규화하고 의무 강도로 분류, 금지 라이선스는 유입 경로와 함께 게이트에서 차단 |
| OSV가 아직 모르는 권고는? | GitHub 미검토 권고처럼 패키지 매핑이 없는 CVE를 NVD 제품 단위(CPE)로 보완 점검. 제품당 한 번만 보고 |
| 다른 도구·조직에 넘길 수 있는가? | 배포 클래스패스만 담은 CycloneDX 1.6 SBOM. 라이선스 식, 의존 관계, 예외 근거를 담은 VEX 분석 상태 포함 |
| 코드를 안 바꿔도 새 CVE가 나오면? 어느 서비스가 영향받나? | [서버](docs/server.md): CI가 올린 SBOM을 저장하고 매일 OSV와 다시 대조. CVE 번호로 영향받는 프로젝트 조회 |

## 만든 계기

직접 개발한 Spring Boot 서비스(경매톡)의 외부 라이브러리를 점검하면서 시작했습니다. OSV-Scanner는 45개 패키지에서 권고 167건을 보여줬습니다. 하지만 그 결과만으로는 아래를 판단할 수 없었습니다.

- 테스트 전용 구성까지 섞인 결과 중 실제 배포물에 해당하는 것은 무엇인가
- `nimbus-jose-jwt`는 왜 Spring Security가 요구한 9.37.3이 아니라 9.37인가
  - 확인해 보니 코드에서 쓰지도 않는 직접 선언이 dependency-management 플러그인 규칙으로 더 높은 요청을 덮어쓰고 있었습니다.
- Spring Framework 6.1.14의 권고는 패치 업그레이드로 해결되는가
  - 6.1 라인에는 공개 수정 버전이 없어 다음 라인으로 옮겨야 했습니다.
- 수정 버전으로 표시된 Tomcat 10.1.58을 쓰면 되는가
  - Maven Central에 배포된 적이 없는 버전이었습니다.

적용 결과는 [사례: 경매톡](docs/case-study/gyeongmaetalk.md)에 근거 파일과 함께 정리했습니다.

## 동작 방식

```
분석 대상 빌드 ──(init script, 빌드 파일 수정 없음)──▶ 구성별 해석 그래프 JSON
                                                          │
                       OSV /v1/querybatch + /v1/vulns ◀───┤ purl 변환
                       Maven Central maven-metadata  ◀───┤ 수정 버전 실배포 확인
                                                          ▼
              버전 결정 분류 · 유입 경로 · 수정 버전 · 수정 지점 · 정책 게이트
                                                          ▼
                     analysis.json · report.md · gate.md · 종료 코드
```

1. **추출** ([init/deptrace.init.gradle](init/deptrace.init.gradle))
   - Gradle의 `ResolutionResult` API에서 구성별로 노드를 뽑습니다. 노드는 선택된 구성요소와 선택 사유입니다.
   - 엣지(요청 좌표·버전 → 선택된 구성요소, 제약 여부)도 함께 뽑습니다.
   - dependency-management 플러그인이 관리하는 버전과 직접 선언된 의존성도 기록합니다.
   - **Maven** ([MavenTreeParser](src/main/java/deptrace/maven/MavenTreeParser.java), [ADR 0007](docs/adr/0007-maven-extraction.md))
     - Maven이 직접 해석한 결과(`dependency:tree -Dverbose`)를 같은 그래프 형식으로 옮깁니다. 해석 규칙을 다시 구현하지 않습니다.
     - `omitted for conflict with`는 nearest-wins 충돌 해결로, `version managed from`은 dependencyManagement의 덮어쓰기로 기록합니다.
     - 직접 의존성에 버전이 적혀 있는지는 pom.xml에서 읽습니다.
     - 구성은 `maven:runtime`(compile·runtime, 기준 구성)과 `maven:test`(전체) 두 개입니다.
2. **버전 결정 분류** ([VersionDecisionClassifier](src/main/java/deptrace/analysis/VersionDecisionClassifier.java))
   - 요청 버전, 선택 버전·사유, 직접 선언·BOM 관리 버전을 비교합니다.
   - Gradle 기본 충돌 해결은 항상 높은 버전을 고릅니다. 하지만 BOM 규칙이나 직접 선언은 요청보다 낮은 버전을 강제할 수 있어서, 이 **하향**을 별도로 표시합니다.
   - 요청한 버전 범위(`[1.3.3,2.4.10]`) 밖의 버전이 선택된 경우도 표시합니다.
3. **유입 경로** ([PathTracer](src/main/java/deptrace/analysis/PathTracer.java))
   - 모든 단순 경로는 그래프가 커지면 기하급수적으로 늘어납니다. 그래서 직접 의존성마다 BFS로 최단 경로 하나만 구합니다.
   - 비용은 O(직접 의존성 수 × (V+E))입니다.
   - BOM/platform 제약 엣지는 버전에만 영향을 줄 뿐 유입 경로가 아니므로 제외합니다.
4. **수정 버전** ([FixVersionResolver](src/main/java/deptrace/osv/FixVersionResolver.java), [PublishedVersions](src/main/java/deptrace/repository/PublishedVersions.java))
   - OSV 영향 범위 이벤트(introduced/fixed/last_affected)를 Maven 버전 순으로 정렬해 상태 기계로 해석합니다.
   - 결과는 세 가지로 구분합니다.
     - **같은 라인 수정 버전**
     - **어떤 영향 범위에도 걸리지 않는 다음 안전 버전**
     - **다른 좌표에만 있는 수정 버전**: 좌표 이동이나 포크의 단서
   - 그 수정 버전이 Maven Central에 실제로 배포됐는지 확인하고, 아니면 배포된 가장 낮은 정식 버전으로 바꿉니다.
5. **수정 지점** ([Remediation](src/main/java/deptrace/analysis/Remediation.java))

   | 분류 | 조건 | 권고 |
   |---|---|---|
   | `REMOVE_DIRECT_PIN` | 직접 선언이 더 높은 요청을 덮어씀 | 선언 제거 |
   | `UPDATE_DIRECT` | 직접 선언 | 선언 버전 상향 |
   | `UPGRADE_PLATFORM` | BOM 관리 | Spring Boot 업그레이드 또는 BOM 속성 |
   | `CONSTRAIN_TRANSITIVE` | 전이 의존성 | 유입자 업그레이드 또는 constraints |
   | `NO_FIX` | 수정 버전 없음 | 제거·대체 또는 근거 있는 예외 |
   | `TEST_ONLY` | 배포 범위 밖 | 보고만 함 |

6. **정책 게이트** ([PolicyGate](src/main/java/deptrace/policy/PolicyGate.java))
   - 배포 클래스패스에서 기준 심각도 이상이면 실패시킵니다.
   - 예외는 사유(reason)와 만료일(expires)이 있어야만 인정하고, 만료되면 다시 실패시킵니다.

7. **라이선스** ([license 패키지](src/main/java/deptrace/license), [ADR 0004](docs/adr/0004-license-identification.md))
   - 배포 클래스패스 구성요소마다 Maven Central의 POM을 받아 `<licenses>`를 읽습니다. 자기 POM에 없으면 부모 POM을 따라 올라갑니다(경매톡 292개 중 105개가 상속).
   - "The Apache Software License, Version 2.0", "Apache 2", "ASL 2.0" 같은 자유 형식 표기를 SPDX 식별자로 정규화합니다. 이름을 먼저 보고, 없으면 URL을 봅니다.
     - 이름을 먼저 보는 이유: "v2.1 **or later**"나 "GPL2 **w/ CPE**"처럼 URL에는 드러나지 않는 조건이 이름에만 있기 때문입니다.
     - 식별하지 못한 값은 추측하지 않고 미확인(UNKNOWN)으로 남깁니다.
   - 의무 강도로 분류합니다: 허용형 / 약한 카피레프트(LGPL·EPL·MPL·CDDL·GPL+Classpath 예외) / 강한 카피레프트(GPL) / 네트워크 카피레프트(AGPL·SSPL) / 미확인.
   - 여러 라이선스가 선언되면 그중 하나를 고를 수 있다(OR)고 봅니다. 금지되지 않은 선택지가 하나라도 있으면 위반이 아니고, 어떤 선택지를 가정했는지 리포트에 남깁니다.
   - 정책 파일로 분류 단위 금지·검토, SPDX 식별자 단위 허용·금지, 사유·만료일이 있는 예외를 지정합니다.

8. **SBOM** ([CycloneDxWriter](src/main/java/deptrace/sbom/CycloneDxWriter.java), [ADR 0005](docs/adr/0005-sbom-scope-and-vex.md))
   - 배포 클래스패스(`productionRuntimeClasspath`)만 담습니다. 테스트·빌드 도구(컴파일러, 어노테이션 프로세서)는 배포물에 없으므로 넣지 않습니다.
   - 라이선스는 단일 식별자면 `license.id`, OR·WITH가 있으면 `expression`, 식별하지 못하면 원문을 `license.name`으로 씁니다.
   - 의존 관계는 실제 유입 엣지만 씁니다. BOM 제약 엣지는 버전만 정할 뿐 구성요소를 끌어오지 않습니다.
   - `analyze` 결과를 주면 취약점을 붙입니다. 유효한 예외는 VEX `not_affected`(근거·재검토일 포함), 나머지는 `in_triage`로 둡니다. 확인하지 않은 "취약함"은 단정하지 않습니다.
   - 버전 선택 사유와 라이선스 상속 출처는 표준 필드가 없어 `deptrace:*` 속성으로 남깁니다.

9. **NVD 보완 점검** ([nvd 패키지](src/main/java/deptrace/nvd), [ADR 0006](docs/adr/0006-nvd-gap-check.md))
   - OSV는 GitHub이 검토한 권고만 Maven 좌표에 연결합니다. 검토 전 권고는 NVD에만 있고, NVD는 jar가 아니라 제품(CPE) 단위로 범위를 적습니다.
   - [제품 대응표](src/main/resources/deptrace/nvd/products.yml)로 Maven 모듈을 NVD 제품에 **명시적으로** 연결합니다. jar 이름에서 추측하지 않습니다.
   - NVD 설정의 AND/OR 논리를 그대로 평가합니다. 다른 제품 조건은 클래스패스 버전으로 확인하고, OS 같은 확인할 수 없는 조건은 해당하지 않는 것으로 봅니다. target_sw가 Java가 아니거나 버전이 `-`(해당 없음)이면 제외합니다.
   - OSV가 이미 보고한 CVE와, GitHub이 검토해 다른 Maven 패키지에 연결한 CVE는 뺍니다. 남은 것을 제품당 한 번 보고하고, 범위 밖이면서 Maven Central에 실제로 배포된 다음 버전을 붙입니다.

## 서버

CLI와 같은 분석 코드를 쓰는 Spring Boot 서버입니다([`server/`](server), [문서](docs/server.md), [ADR 0008](docs/adr/0008-server-design.md)).

- CI가 `deptrace sbom` 결과를 올리면 프로젝트의 스냅샷으로 저장하고, 발견을 OPEN·RESOLVED로 관리합니다.
- Spring Batch 잡이 매일 사용 중인 구성요소를 중복 없이 OSV에 다시 조회해, 코드 변경 없이 공개된 권고를 찾고 웹훅으로 알립니다.
- `GET /api/advisories/CVE-…/impact`로 영향받는 프로젝트를, `GET /api/components/usage?module=…`로 라이브러리를 쓰는 프로젝트를 찾습니다.
- "버전 ↔ 권고" 대응은 전역으로 한 번만 계산하고, 프로젝트별 발견은 유일 제약으로 멱등하게 맞춥니다. OSV 호출은 DB 트랜잭션 밖에서 합니다.
- Spring Boot 3.5, JPA, PostgreSQL(Flyway), Spring Batch, Testcontainers 통합 테스트 7개. 실제 OSV로 세 프로젝트를 올렸을 때 발견 수가 CLI와 일치했습니다.

## 기존 도구와의 역할 분담

| 영역 | 그대로 사용 | 직접 구현 |
|---|---|---|
| 의존성 해석 | Gradle (해석 규칙의 정답) | 해석 결과를 선택 사유와 함께 추출하는 init script |
| 취약점 데이터 | OSV API (GitHub Advisory Database 등 집계) | 배치 조회·캐시, CVE↔GHSA 별칭 병합 |
| 버전 비교 | maven-artifact `ComparableVersion`, `VersionRange` | 영향 범위 상태 기계, 라인 변경·실배포 판단 |
| 탐지 결과 교차 검증 | OSV-Scanner | 차분 비교 기준으로만 사용 |
| 업데이트 PR | Dependabot·Renovate 등 | 수정 전후 diff로 의도하지 않은 변화 확인 |

해석 엔진과 버전 비교 규칙은 기준 구현을 그대로 썼습니다. 다시 만들면 오차만 생기기 때문입니다. 근거는 [ADR 0001](docs/adr/0001-gradle-resolution-result.md), [ADR 0002](docs/adr/0002-osv-matching-and-fix-version.md)에 있습니다.

## 사용법

```bash
./gradlew installDist
```

분석 대상 프로젝트에서 해석 그래프를 추출합니다(빌드 파일 수정 없음).

```bash
./gradlew -I /path/to/deptrace/init/deptrace.init.gradle deptraceExport --no-configuration-cache
```

Maven 프로젝트는 아래처럼 추출합니다. 프로젝트의 `mvnw`(없으면 `mvn`)로 maven-dependency-plugin 3.9.0을 실행하고, 결과를 `target/deptrace`에 씁니다. 이후 명령은 `--graphs target/deptrace`로 같습니다.

```bash
deptrace maven-export --project .
```

| 명령 | 설명 |
|---|---|
| `deptrace maven-export --project .` | Maven 프로젝트의 해석 그래프 추출 (`target/deptrace`) |
| `deptrace explain --graphs build/deptrace com.nimbusds:nimbus-jose-jwt` | 구성요소 하나의 버전 결정 원인과 유입 경로 (오프라인) |
| `deptrace analyze --graphs build/deptrace --out build/deptrace-report --fail-on HIGH --exceptions deptrace-exceptions.yml` | 전체 분석, 리포트 생성, 정책 게이트 (위반 시 종료 코드 1) |
| `deptrace nvd-gaps --graphs build/deptrace --analysis build/deptrace-report/analysis.json` | OSV 미반영 권고 보완 점검 (`NVD_API_KEY`, `GITHUB_TOKEN` 환경 변수 권장) |
| `deptrace licenses --graphs build/deptrace --policy deptrace-licenses.yml` | 라이선스 판정과 라이선스 게이트 (금지 라이선스가 있으면 종료 코드 1) |
| `deptrace sbom --graphs build/deptrace --analysis build/deptrace-report/analysis.json --exceptions deptrace-exceptions.yml` | CycloneDX 1.6 SBOM (VEX 포함) |
| `deptrace diff --before before/analysis.json --after after/analysis.json --out diff.md` | 수정 전후 비교 |

CI 예시는 [경매톡 워크플로](docs/case-study/gyeongmaetalk.md#자동화)를 참고하세요.

`explain` 출력 예 (경매톡, 수정 전):

```
com.nimbusds:nimbus-jose-jwt:9.37  [productionRuntimeClasspath]
  선택 사유(Gradle): REQUESTED, SELECTED_BY_RULE
  요청 버전: 9.37, 9.37.3  직접 선언: 9.37  BOM 관리: -
  분류: DIRECT_OVERRIDE — 직접 선언한 버전(9.37)이 다른 라이브러리의 요청 9.37.3보다 우선 적용됨 · 요청된 더 높은 버전 대신 낮은 버전이 선택된 하향
  유입 (직접 의존성 2개):
    com.nimbusds:nimbus-jose-jwt:9.37
    org.springframework.boot:spring-boot-starter-oauth2-client:3.3.5 → org.springframework.security:spring-security-oauth2-jose:6.3.4 → com.nimbusds:nimbus-jose-jwt:9.37
```

## 검증

- 단위 테스트 82개 (`./gradlew test`)
  - 버전 결정 분류: 하향, BOM 덮어쓰기, 범위 이탈, 충돌 해결
  - 유입 경로: 최단 경로, 제약 엣지 제외, 순환
  - 영향 범위 해석: 라인 변경, 재발 범위, 정렬, 좌표 이동
  - 실배포 버전 선택(변형 꼬리표 유지 포함), 정책 게이트(예외 만료·패키지 불일치·설정 오류), 전후 비교
  - 라이선스: POM 해석(부모 상속, 순환, XXE 차단), SPDX 정규화(구체적 URL 우선, or-later·예외 조항), 다중 라이선스 선택, 정책·예외
  - SBOM: CycloneDX 공식 라이브러리(cyclonedx-core-java)로 1.6 스키마 검증, 라이선스 표현 구분, 제약 엣지 제외, VEX 상태
  - NVD 보완: 라인별 범위, Java 외 target_sw 제외, 버전 `-` 제외, AND 조건, 변형 꼬리표, 제품 단위 집계, 다음 안전 버전, 게이트
- Maven 추출 정확도: spring-batch-extensions 6개 모듈에서 Maven의 `dependency:list` 결과와 비교해, 실행 범위 357개·전체 525개 구성요소가 **모두 일치**했습니다(누락 0, 초과 0). [사례](docs/case-study/spring-batch-extensions.md)
- NVD 보완 점검 정확도: Dependency-Check 교차 검증에서 OSV가 놓친 것으로 확인한 26건을 기준으로 **26건 모두 찾았고(재현율 100%), 추가 보고는 0건**, Dependency-Check의 오탐 CVE 13건은 하나도 보고하지 않았습니다([사례 12절](docs/case-study/gyeongmaetalk.md#12-osv-미반영-권고-보완-2026-11-18)).
- SBOM 교차 검증: 경매톡에서 CycloneDX Gradle 플러그인 3.6.1의 결과와 비교했습니다. 배포 구성요소 292개가 모두 일치했고, 차이는 [사례 문서](docs/case-study/gyeongmaetalk.md#10-sbom과-공식-플러그인-비교-2026-11-18)에 정리했습니다.
- 테스트 데이터는 경매톡에서 실제로 관찰한 사례(nimbus-jose-jwt, querydsl, json-smart, httpclient5, protobuf, ion-java, Tomcat 10.1.58, guava 33.7.2-jre)를 그대로 옮겼습니다.
- OSV-Scanner와의 차분 비교: 경매톡 배포 클래스패스 기준 (구성요소, 권고 ID) 163쌍이 모두 일치했습니다.

## 한계와 다음 단계

- **도달 가능성:** 함수 단위 도달 가능성은 분석하지 않습니다. 예외 판단의 근거는 기능 단위 코드 검색이며, 사람이 판단합니다.
- **빌드 시스템:** Gradle과 Maven을 지원합니다.
  - Maven은 모듈 하나씩 추출합니다. 멀티 모듈 프로젝트(reactor)는 모듈마다 실행해야 합니다.
  - Maven 그래프는 group:artifact:version 단위라, classifier만 다른 jar(예: netty-tcnative의 OS별 jar)를 구분하지 않습니다.
  - 빌드를 실행할 수 없는 입력(매니페스트만 있는 경우)은 지원하지 않습니다. 다음 단계는 정적 해석기를 만들고, Gradle·Maven 추출 결과를 정답 데이터로 삼아 정확도를 측정하는 것입니다.
- **바이너리 분석:** bootJar 안의 JAR와 재패키징(shading)된 라이브러리 식별은 하지 않습니다. 해석 그래프에 나타나지 않는 구성요소는 보지 못합니다.
- **데이터 범위:** 취약점 데이터는 OSV에 의존합니다.
  - OSV는 GitHub이 **검토한** 권고만 Maven 좌표에 연결합니다. 미검토(unreviewed) 권고는 보지 못합니다.
  - 경매톡에서 OWASP Dependency-Check와 비교해 보니, 이 때문에 놓친 CVE가 26건(CRITICAL 포함)이었습니다([사례 11절](docs/case-study/gyeongmaetalk.md#11-owasp-dependency-check와-교차-검증-2026-11-18)).
  - `nvd-gaps`로 보완했지만, [제품 대응표](src/main/resources/deptrace/nvd/products.yml)에 있는 제품(현재 14개)만 봅니다. 표에 없는 라이브러리의 미검토 권고는 여전히 보지 못합니다.
  - NVD는 제품 단위라 어느 jar의 문제인지 알려주지 않습니다. 보고는 제품 단위로 하고, 해당 기능을 쓰는지는 사람이 확인합니다.
- **라이선스:** POM 선언만 봅니다.
  - JAR 안의 LICENSE 파일, 소스 파일 헤더, 재패키징된 코드의 원래 라이선스는 보지 않습니다. POM 선언이 실제와 다른 경우를 잡지 못합니다.
  - 다중 라이선스를 OR로 보는 것은 Maven 관례에 따른 가정이라, AND 의미로 나열한 프로젝트는 사람이 확인해야 합니다.
  - 라이선스 간 호환성(예: Apache-2.0과 GPL-2.0의 결합)과 고지 의무 이행(NOTICE 파일 수집)은 다루지 않습니다.
