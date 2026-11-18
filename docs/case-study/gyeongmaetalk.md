# 사례: 경매톡 백엔드 의존성 취약점 점검과 해결

| 항목 | 내용 |
|---|---|
| 대상 | [gyeongmaetalk/gyeongmaetalk-BE](https://github.com/gyeongmaetalk/gyeongmaetalk-BE) — Java 17, Spring Boot 3.3.5, Gradle 8.14.3, io.spring.dependency-management 1.1.7 |
| 기준 커밋 | `refactor/s3-lifecycle-cleanup` 7958acf (2026-09-11, 가장 최근 푸시된 코드) |
| 마지막 배포 | main e2c43d1 (GitHub Actions Main Deploy, 2026-06-11). main과 기준 커밋의 배포 클래스패스는 같음 |
| 점검일 | 2026-10-19 |
| 근거 파일 | [baseline/](gyeongmaetalk/baseline), [after/](gyeongmaetalk/after), [diff.md](gyeongmaetalk/diff.md) |

## 1. 문제 인식

외부 라이브러리 의존도가 높은 서비스입니다. OAuth2·JWT 로그인(카카오·애플), 토스·인앱 결제 검증, FCM, S3 등을 씁니다. 그런데 실제로 어떤 오픈소스가 어떤 버전으로 배포되는지 확인해 본 적이 없었습니다.

## 2. 식별과 확인

| 도구·출처 | 결과 |
|---|---|
| `gradle dependencies` (구성별) | 배포 클래스패스(`productionRuntimeClasspath`) 구성요소 269개 |
| OSV-Scanner 2.7.0 (Gradle 잠금 파일 입력) | 45개 패키지, 권고 167건. 테스트·빌드 도구 구성이 섞여 있음 |
| DepTrace | 배포 클래스패스 기준 취약 구성요소 41개, 중복 제거 시 고유 취약점 152건(CRITICAL 13, HIGH 58, MODERATE 64, LOW 17). 테스트 전용 2개(assertj-core, xmlunit-core)는 분리 |
| 권고 확인 | osv.dev, GitHub Advisory Database(GHSA), 각 프로젝트 릴리스 노트, Maven Central 메타데이터 |

**버전 결정 원인으로 다시 나누면** 수정 지점이 달라집니다.

| 분류 | 구성요소 수 | 예 |
|---|---|---|
| Spring Boot BOM 관리 | 34 | spring-webmvc 6.1.14, tomcat-embed-core 10.1.31, netty 4.1.114.Final, jackson-databind 2.17.2 |
| 전이 의존성 | 4 | protobuf-java 3.25.1(충돌 해결), grpc-netty-shaded 1.50.1, bcprov-jdk18on 1.83, aws-java-sdk-s3 1.11.792 |
| 직접 선언 | 1 | nimbus-jose-jwt 9.37 |
| 수정 버전 없음 | 2 | querydsl-jpa 5.0.0, ion-java 1.0.2 |

## 3. 원인 분석

**nimbus-jose-jwt 9.37 (CVE-2023-52428, HIGH)**
- 2025-09-23 애플 로그인 구현 커밋에서 직접 선언됐지만, 코드에서 `com.nimbusds`를 쓰는 곳은 없었습니다.
- Spring Security(oauth2-jose 6.3.4)와 oauth2-oidc-sdk는 9.37.3을 요청했습니다.
- dependency-management 플러그인은 직접 선언 버전을 규칙(`SELECTED_BY_RULE`)으로 적용해, 더 높은 요청을 덮어쓰고 9.37로 **하향**시켰습니다.
- Gradle 기본 충돌 해결이었다면 9.37.3이 선택됐을 것입니다.

**spring-cloud-starter-aws 2.2.6.RELEASE**
- 실제 S3 코드는 AWS SDK v2(`S3Client`, `S3Presigner`)만 씁니다.
- 그런데 SDK v1 `AmazonS3Client` 빈이 정의만 된 채 남아 있었습니다.
- 이 스타터 때문에 aws-java-sdk 1.11.792와 ion-java 1.0.2가 들어왔습니다.
- ion-java 권고(CVE-2024-21634)는 `software.amazon.ion` 좌표에는 수정 버전이 없고, `com.amazon.ion:ion-java` 1.10.5에만 있습니다(좌표 이동).

**Spring Framework 6.1.14**
- OSV 영향 범위가 6.1 라인에서는 `last_affected 6.1.21`로 끝납니다. 공개 수정 버전은 6.2.x에만 있습니다.
- 패치 업그레이드로는 해결되지 않고 Spring Boot 마이너 업그레이드가 필요했습니다.

**json-smart 2.5.1**
- oauth2-oidc-sdk가 요청한 범위 `[1.3.3,2.4.10]` 밖의 버전을 BOM이 선택하고 있었습니다.

## 4. 해결 방안 결정

임시 사본에서 두 안을 측정한 뒤 결정했습니다.

| 안 | 고유 취약점 | 판단 |
|---|---|---|
| A. Boot 3.3.5 유지, 개별 수정 | 152 → 146 | BOM 관리 구성요소가 대부분이라 효과가 작음 |
| B. Boot 3.5.16 + 개별 수정 | 152 → 38 | 채택. 3.x 최신 패치라 javax→jakarta 같은 메이저 변경 없이 대부분 해소 |

판단 기준은 다섯 가지였습니다.
1. 배포물에 포함되는가
2. 공개 수정 버전이 있는가
3. BOM이 검증한 버전 조합을 유지하는가
4. 변경 범위(diff로 확인)
5. 기존 테스트 결과가 같은가

Spring Boot 4(Spring Framework 7) 이전은 메이저 변경이라 이번 범위에서 제외했습니다.

**최종 변경** (`chore/dependency-security-update`)

- Spring Boot 3.3.5 → 3.5.16, springdoc 2.2.0 → 2.8.17
- nimbus-jose-jwt 직접 선언 제거 → Spring Security가 요청한 10.9.1 선택
- spring-cloud-starter-aws와 미사용 v1 빈 제거 → aws-java-sdk·ion-java 제거
- firebase-admin 9.1.1 → 9.11.0 → grpc-netty-shaded 1.83.0
- BOM 속성 패치: Tomcat 10.1.59, Netty 4.1.137.Final, Jackson 2.21.7
  - Boot 3.5.16 BOM이 아직 반영하지 않은 같은 라인 패치입니다.
  - Tomcat은 OSV 수정 버전 10.1.58이 Maven Central에 배포된 적이 없어 10.1.59로 정했습니다.
- bcprov-jdk18on 1.85 하한 지정

## 5. 변경과 테스트, 그리고 테스트가 잡은 문제

변경 직후 기존 테스트 113개 중 **3개가 새로 실패**했습니다(주문 생성, S3 presigned URL 2건).

| 단계 | 내용 |
|---|---|
| 증상 | 응답 JSON에 `result`가 없음 |
| 확인 | MockMvc로 응답을 출력해 보니 `Content-Type: application/xml` |
| 원인 | firebase-admin 9.11.0 → google-cloud-storage 2.73.0이 `jackson-dataformat-xml`을 끌어옴. Spring MVC는 XML 변환기를 JSON보다 먼저 등록하므로, Accept 헤더가 없는 요청에 XML로 응답 |
| 판단 | 앱은 Firebase 중 FCM(`FirebaseMessaging`)만 쓰고 Storage는 쓰지 않음 |
| 조치 | firebase-admin에서 `jackson-dataformat-xml` 제외 |

같은 업그레이드에서 BOM 하향도 하나 더 나왔습니다.

| 단계 | 내용 |
|---|---|
| 증상 | httpcore5 5.3.6에 CVE-2026-54399(HIGH) |
| 원인 | firebase-admin이 httpclient5 5.6.4를 요청했지만 Spring Boot BOM이 5.5.2로 하향시켜, 그 결과 httpcore5 5.3.6이 선택됨 |
| 조치 | BOM 속성(`httpclient5.version`, `httpcore5.version`)으로 라이브러리가 요청한 버전을 복원 |

okhttp logging-interceptor는 Boot 3.5가 okhttp 관리를 중단하면서 4.12.0 → 4.10.0으로 하향될 뻔했습니다. constraints로 4.12.0을 유지했습니다.

**최종 테스트:** 113개 중 112개 통과로 수정 전과 같습니다. 실패 1건은 저장소에 `application.yml`이 없어 원래부터 실패하는 `contextLoads`입니다. bootJar 빌드도 성공했습니다.

## 6. 재검증

| 항목 | 수정 전 | 수정 후 |
|---|---|---|
| 배포 클래스패스 구성요소 | 269 | 292 |
| 취약 구성요소 | 41 | 6 |
| 고유 취약점 | 152 (CRITICAL 13, HIGH 58, MODERATE 64, LOW 17) | 7 (CRITICAL 3, HIGH 1, MODERATE 3) |
| OSV-Scanner 권고 항목 (전 구성) | 167 | 9 |
| 구성요소 변화 | — | 상향 180, 하향 0, 추가 41, 제거 18 |

- (모듈, 취약점) 기준으로 해결 158쌍, 신규 3쌍, 잔존 5쌍입니다.
- 신규 중 CVE-2026-47890(SSE)은 6.2 라인에만 영향을 주는 권고라, 업그레이드로 새로 노출된 것입니다. 예외 근거에 포함했습니다.

## 7. 수정 불가 권고의 처리

[deptrace-exceptions.yml](https://github.com/gyeongmaetalk/gyeongmaetalk-BE/blob/chore/dependency-security-update/deptrace-exceptions.yml)에 근거와 만료일(2027-01-19)을 붙여 등록했습니다.

| 권고 | 근거 |
|---|---|
| CVE-2026-47892 (WebFlux 함수형 엔드포인트) | WebFlux는 WebClient로만 사용, RouterFunction 없음 |
| CVE-2026-47890 (SSE 렌더링) | SseEmitter·ServerSentEvent 없음 |
| CVE-2026-47884 (XsltView) | XsltView 없음 |
| CVE-2024-49203 (querydsl orderBy HQL 인젝션) | 유일한 orderBy가 `counsel.createdAt.desc()` 고정 정렬. 수정은 OpenFeign 포크로 좌표 이전이 필요해 후속 과제 |

- Spring 권고 3건은 Spring Framework 7.0.9에서만 수정됐습니다.
- MODERATE 3건(opentelemetry-api, commons-lang3, log4j-api)은 게이트 기준 미만이라 다음 Spring Boot 패치에서 다시 확인합니다.

## 자동화

[.github/workflows/dependency-audit.yml](https://github.com/gyeongmaetalk/gyeongmaetalk-BE/blob/chore/dependency-security-update/.github/workflows/dependency-audit.yml)이 다음을 수행합니다.

- **실행 시점:** 빌드 파일·예외 목록이 바뀔 때, 매일 09:00 KST(코드 변경 없이 공개되는 신규 취약점 대응), 수동 실행
- **처리 순서:** init script로 해석 그래프 추출 → `deptrace analyze --fail-on HIGH --exceptions deptrace-exceptions.yml`
- **결과:** 게이트 결과와 리포트를 실행 요약에 출력
- **만료 관리:** 예외가 만료되면 다시 실패합니다.

로컬에서 같은 단계를 실행했을 때 게이트는 수정 전 커밋에서 위반 74건으로 실패, 수정 후 커밋에서 예외 5건 인정으로 통과했습니다.

## 8. 점검 이후: 게이트가 잡은 신규 취약점 (2026-11-18)

브랜치를 올리자 [첫 감사 실행](https://github.com/gyeongmaetalk/gyeongmaetalk-BE/actions/runs/44227648269)이 실패했습니다. 코드는 10월 점검 때와 같았습니다.

| 항목 | 내용 |
|---|---|
| 검출 | `com.google.guava:guava:33.6.0-jre` — GHSA-xxph-c9ww-hj94 (HIGH, 역직렬화 시 통제되지 않은 메모리 할당) |
| 공개일 | 2026-10-27, 점검 8일 뒤 |
| 유입 | firebase-admin 9.11.0, google-auth-library-oauth2-http 1.52.0, google-api-client 2.7.2를 거친 전이 의존성 |
| OSV 수정 버전 | 33.7.2. 하지만 Maven Central에는 `33.7.2-jre`와 `33.7.2-android`만 배포됨 |

**DepTrace 자체의 결함도 함께 드러났습니다.** 리포트가 `33.7.2-android`를 권고했습니다.
- 원인: Maven 버전 비교에서 한정자는 사전순이라 `-android`가 `-jre`보다 낮습니다. "배포된 가장 낮은 버전"을 고르면 다른 변형이 선택됩니다.
- `-android`는 Android용 API 제약을 둔 변형이라, `-jre`를 쓰던 서버에 그대로 적용하면 의도하지 않은 변경이 됩니다.
- 수정: 현재 버전의 변형 꼬리표(`jre`, `android`, `jre11` 등)를 유지하는 후보를 먼저 고르고, 같은 변형이 없을 때만 다른 변형으로 넘어가게 했습니다. `Final`, `RELEASE` 같은 정식 표기와 사전 배포 표기는 변형으로 보지 않습니다. 테스트 4개를 추가했습니다.

**조치:** `constraints`로 `guava:33.7.2-jre` 하한을 지정했습니다 ([599583e](https://github.com/gyeongmaetalk/gyeongmaetalk-BE/commit/599583e)).
- 게이트: 통과, 예외 5건 인정
- 배포 클래스패스: 취약 구성요소 6개, 고유 취약점 8건 (CRITICAL 3, HIGH 1, MODERATE 4)
  - 10월보다 MODERATE가 1건 늘었습니다. 점검 이후 공개된 권고이고, 게이트 기준(HIGH) 미만이라 다음 Spring Boot 패치에서 다시 확인합니다.
- 테스트: 113개 중 112개 통과로 기존과 같습니다.

매일 실행하는 게이트를 둔 이유가 그대로 확인된 사례입니다. 코드가 바뀌지 않아도 공개된 취약점 데이터가 바뀌면 결과가 바뀝니다.

## 9. 라이선스 점검 (2026-11-18)

`deptrace licenses`로 배포 클래스패스 292개의 POM 라이선스를 판정했습니다([ADR 0004](../adr/0004-license-identification.md)).

| 분류 | 구성요소 수 | 예 |
|---|---|---|
| 허용형 | 284 | Apache-2.0 249, BSD-3-Clause 20, MIT 11 |
| 약한 카피레프트 | 7 | logback(EPL-2.0 / LGPL-2.1), hibernate-core(LGPL-2.1-or-later), jakarta.annotation·transaction(EPL-2.0 / GPL2+Classpath 예외), aspectjweaver(EPL-2.0) |
| 강한 카피레프트 | 1 | mysql-connector-j 9.7.0 (GPL-2.0 + Universal FOSS Exception) |

- 292개 중 105개는 자기 POM에 선언이 없어 부모 POM에서 상속받았습니다.
- Apache-2.0 하나가 7가지 표기로 적혀 있었습니다.

**첫 실행에서 판정이 틀린 3건을 찾아 고쳤습니다.**
- MIT-0이 MIT로 묶임: MIT URL이 MIT-0 URL의 앞부분이라 부분 일치에 걸렸습니다. 더 긴 URL을 우선하게 했습니다.
- hibernate-core의 "v2.1 or later"가 `LGPL-2.1-only`로 판정됨: "or later"는 이름에만 있고 URL은 같습니다. 이름을 URL보다 먼저 보게 했습니다.
- 이름 자리에 SPDX 식별자를 그대로 쓴 POM(logback의 `LGPL-2.1-only`)을 URL 없이는 인식하지 못함: SPDX 식별자를 직접 인식하게 했습니다.

### MySQL Connector/J 판단

| 단계 | 내용 |
|---|---|
| 판정 | GPL-2.0 + Universal FOSS Exception. 이름이 비슷한 Classpath 예외와 달리, FOSS 예외는 결합한 프로그램이 오픈소스 라이선스일 때만 GPL 전파를 면제합니다. 비공개 소스인 경매톡에는 적용되지 않으므로 강한 카피레프트로 분류했고, 기본 정책에서 게이트가 실패했습니다. |
| 의무 발생 조건 확인 | GPL의 소스 공개 의무는 바이너리를 배포할 때 생깁니다. 서버에서만 실행하면 생기지 않습니다. 그래서 실제 배포 경로를 확인했습니다. |
| 배포 경로에서 발견한 것 | 배포 워크플로가 jar를 담은 Docker 이미지를 **공개** Docker Hub 저장소에 push하고 있었습니다. 엄밀히는 GPL 구성요소를 포함한 바이너리를 외부에 배포한 상태였습니다. |
| 조치 | 공개 이미지 배포를 중단했습니다(2026-11-18). |
| 대안 비교 | MariaDB Connector/J(LGPL-2.1)로 교체하면 리스크 자체가 없어집니다. 하지만 서버를 내린 상태라 실제 DB 연결로 동작을 검증할 수 없었습니다. 코드는 JDBC 표준 API만 쓰고 `com.mysql` 클래스를 직접 참조하지 않아(src/main 검색 0건), 나중에 교체할 때 영향 범위는 작습니다. |
| 결정 | [deptrace-licenses.yml](https://github.com/gyeongmaetalk/gyeongmaetalk-BE/blob/chore/dependency-security-update/deptrace-licenses.yml)에 근거와 **전환 조건**("배포 형태가 바뀌면 MariaDB Connector/J로 교체"), 만료일(2027-05-18)을 붙여 예외로 등록했습니다. |

라이선스 판정 결과만 보면 "GPL이 있다"에서 끝납니다. 의무가 실제로 생기는지는 **배포 형태**에 달려 있어서, 빌드 산출물이 어디로 나가는지까지 확인해야 판단할 수 있었습니다.

### 자동화

감사 워크플로에 라이선스 단계를 추가했습니다. 빌드 파일이나 정책 파일이 바뀔 때, 그리고 매일 실행합니다. 취약점 게이트가 실패해도 라이선스 결과가 함께 보이도록, 해석 그래프 추출만 성공하면 실행합니다.

## 10. SBOM과 공식 플러그인 비교 (2026-11-18)

`deptrace sbom`으로 CycloneDX 1.6 SBOM을 만들고([ADR 0005](../adr/0005-sbom-scope-and-vex.md)), 같은 커밋에서 CycloneDX Gradle 플러그인 3.6.1(기본 설정)의 결과와 비교했습니다. 두 결과 모두 CycloneDX 공식 라이브러리의 1.6 스키마 검증을 통과했습니다.

### 구성요소 범위

| 항목 | DepTrace | 플러그인 |
|---|---|---|
| 구성요소 | 292 | 343 |
| 공통 | 292 (DepTrace 결과 전부) | |
| 플러그인에만 있음 | | 51: 테스트 전용 26(h2, assertj 등), 빌드 도구 25(Kotlin 컴파일러, Lombok, querydsl-apt 등) |
| scope 구분 | 전부 `required` (배포물) | 없음 |

플러그인 결과를 그대로 넘기면, 받는 쪽은 배포 jar에 없는 51개의 취약점과 라이선스까지 대응하게 됩니다. 예를 들어 Lombok은 컴파일할 때만 쓰고 배포물에 들어가지 않습니다.

### 라이선스 표기 (공통 292개 중 13개 차이)

| 구성요소 | DepTrace | 플러그인 | 비고 |
|---|---|---|---|
| mysql-connector-j | `GPL-2.0-only WITH Universal-FOSS-exception-1.0` | `GPL-2.0-only` | 예외 조항을 잃으면 판단 근거(9절)가 사라짐 |
| javax.annotation-api | `CDDL-1.1 OR GPL-2.0-only WITH Classpath-exception-2.0` | `CDDL-1.0 OR GPL-2.0-with-classpath-exception` | POM이 가리키는 LICENSE 원문이 CDDL **1.1**임을 확인. 플러그인 쪽 식별자는 SPDX에서 폐기된 표기 |
| jakarta.annotation·transaction | `EPL-2.0 OR GPL-2.0-only WITH Classpath-exception-2.0` | `EPL-2.0`, `GPL-2.0-with-classpath-exception` (각각) | 플러그인은 다중 라이선스를 별도 항목으로 나열해 AND인지 OR인지 드러나지 않음 |
| logback, jakarta.persistence, HdrHistogram | `A OR B` 식 | 별도 항목 나열 | 위와 같음 |
| hibernate-core | `LGPL-2.1-or-later` | 원문 이름 | 플러그인은 식별하지 못함 |
| google-auth 2개, re2j, bcprov | `BSD-3-Clause`, `MIT` | 원문 이름("BSD New license", "Go License", "Bouncy Castle Licence") | 플러그인은 식별하지 못함 |

### VEX

취약점 8건을 함께 실었습니다.
- 예외로 인정한 4건(Spring 3건, querydsl 1건)은 `not_affected`로 쓰고 사유와 재검토일을 붙였습니다. SSE 권고는 webflux와 webmvc에 함께 걸려, 구성요소 기준으로는 5쌍입니다.
- 게이트 기준(HIGH) 미만인 MODERATE 4건은 `in_triage`입니다. 이 SBOM을 받는 쪽 스캐너는 우리가 이미 검토한 권고를 다시 "취약"으로 띄우지 않을 수 있습니다.

### 자동화

감사 워크플로가 매 실행마다 `bom.cdx.json`을 만들어 리포트 산출물에 함께 올립니다.

## 11. OWASP Dependency-Check와 교차 검증 (2026-11-18)

같은 커밋, 같은 범위(배포 클래스패스)에서 OWASP Dependency-Check 13.0.0(NVD, CPE 매칭)과 DepTrace(OSV, 패키지 좌표 매칭)의 결과를 (구성요소, CVE) 쌍으로 비교했습니다. Dependency-Check는 OSS Index 분석기를 끄고 NVD만 썼습니다. 이 비교의 목적이 CPE 방식 자체를 보는 것이기 때문입니다.

| | 쌍 | 고유 CVE |
|---|---|---|
| DepTrace | 9 | 8 |
| Dependency-Check | 349 | 40 |
| 공통 | 6 | 5 |
| Dependency-Check에만 | **343** | 39 (그중 4건은 다른 모듈에서는 공통) |
| DepTrace에만 | 3 | 3 |

Dependency-Check에만 나온 343쌍을 전부 GitHub Advisory Database(GHSA)와 NVD의 CPE 범위로 하나씩 대조해 세 가지 원인으로 분류했습니다. 분류되지 않고 남은 건 없습니다.

| 원인 | 쌍 | CVE | 판정 | 예 |
|---|---|---|---|---|
| 다른 생태계 | 28 | 7 | **오탐** | OpenTelemetry **Go** SDK의 CVE 5건(CPE의 `target_sw=go`)과 **JavaScript**(npm) CVE 1건이 Java용 opentelemetry jar 15개에 붙음. Kotlin **Gradle 플러그인** CVE가 kotlin-stdlib에 붙음 |
| 같은 프로젝트의 다른 모듈 | 46 | 6 | **오탐** | log4j-**core** 전용 CVE 2건이 log4j-api·log4j-to-slf4j에 붙음. spring-**webmvc**의 XsltView CVE가 spring-core, spring-jdbc 등 13개 모듈에 붙음. CPE가 "Spring Framework" 제품 단위라 jar 단위로 구분하지 못함 |
| 미검토 GHSA | 269 | 26 | **DepTrace 미탐** | Spring Framework 14건, Spring Security 5건, Spring Data JPA, Reactor Netty, Netty, MySQL Connector/J 4건 |

### DepTrace가 놓친 26건

이 26건은 GitHub에 권고가 있지만 아직 **미검토(unreviewed)** 상태입니다. 미검토 권고는 NVD에서 자동으로 가져온 것이라 어느 Maven 패키지에 해당하는지 연결돼 있지 않습니다. OSV는 GitHub이 검토해 패키지에 연결한 권고만 Maven 좌표로 매칭하므로, DepTrace도 이 26건을 보지 못했습니다. Spring 권고들은 공개된 지 약 3개월(2026-08-27)이 지났는데도 미검토 상태였습니다.

NVD의 CPE 범위로 확인하니 26건 모두 경매톡의 현재 버전이 영향 범위 안에 있었습니다. CRITICAL도 포함돼 있습니다. **앞 절의 게이트 "통과"는 OSV에 데이터가 없어서 나온 결과이기도 했습니다.**

| 대상 (현재 버전) | CVE 수 | NVD 수정 버전 | Maven Central 배포 |
|---|---|---|---|
| Spring Framework 6.2.19 | 14 | 6.2.20 | 없음 (공개 수정은 7.0.x) |
| Spring Security 6.5.11 | 5 | 6.5.12 | 없음 |
| Spring Data JPA 3.5.13 | 1 | 3.5.14 | 없음 |
| Reactor Netty 1.2.18 | 1 | 1.2.19 | 없음 |
| Netty 4.1.137.Final | 1 | 4.1.138 | **있음** |
| MySQL Connector/J 9.7.0 | 4 | (9.7.x 영향) | 없음 |

Netty만 같은 라인의 공개 수정 버전이 있습니다. Spring 계열은 6.2·3.5 라인의 공개 수정 버전이 없어, 3절에서 판단한 것과 같이 Spring Boot 4(Spring Framework 7) 이전이 필요합니다.

### DepTrace에만 나온 3건

| 구성요소 | 권고 | Dependency-Check가 놓친 이유 |
|---|---|---|
| querydsl-jpa 5.0.0 | CVE-2024-49203 (HIGH) | jar를 `cpe:...:homepage_project:homepage:5.0.0`이라는 엉뚱한 제품으로 식별해, 실제 querydsl CVE에 연결하지 못함 |
| opentelemetry-api 1.49.0 | GHSA-ccrj-gw8r-854m, GHSA-rcgg-9c38-7xpx (MODERATE) | Dependency-Check 결과에 없음. NVD 쪽에서 이 Java 패키지의 CPE와 연결되지 않은 것으로 보임 |

### 결론

- **두 방식은 서로의 약점을 보완합니다.** CPE 방식은 제품 단위·생태계 구분이 거칠어 오탐이 많습니다(343쌍 중 74쌍, CVE 39건 중 13건). 대신 GitHub이 아직 검토하지 않은 최신 권고를 잡습니다. 좌표 방식은 정확하지만, 검토가 끝나기 전까지는 보지 못합니다.
- **숫자가 많은 쪽이 맞는 것도, 적은 쪽이 맞는 것도 아닙니다.** 343건을 그대로 개발팀에 넘기면 오탐 74쌍과 모듈 중복을 걸러내는 일이 개발자에게 넘어갑니다. 반대로 OSV만 믿으면 CRITICAL을 포함한 26건을 놓칩니다.
- 이 결과는 DepTrace의 한계로 README에 기록했고, 다음 절에서 보완했습니다.

## 12. OSV 미반영 권고 보완 (2026-11-18)

11절에서 찾은 공백을 메우려고 `deptrace nvd-gaps`를 만들었습니다([ADR 0006](../adr/0006-nvd-gap-check.md)). Dependency-Check의 장점(NVD의 최신 권고)은 가져오고, 단점(추측에 의한 제품 식별, jar마다 중복)은 피하는 것이 목표였습니다.

| 설계 | 피하려는 Dependency-Check의 오탐 |
|---|---|
| Maven 모듈 ↔ NVD 제품을 명시적 대응표로 연결 | querydsl → `homepage_project:homepage` |
| target_sw가 Java 계열이 아니면 제외 | Go·JavaScript용 OpenTelemetry 권고 |
| log4j-api는 log4j 제품에 연결하지 않음 | log4j-core 권고가 log4j-api에 |
| 제품당 한 번 보고 | Spring 권고 하나가 jar 15개에 |
| GitHub이 검토해 다른 모듈에 연결한 CVE는 제외 | webmvc 권고가 spring-core 등에 |

### 정확도 측정

11절에서 OSV가 놓쳤다고 확인한 26건을 기준으로 측정했습니다.

| 지표 | 첫 구현 | 수정 후 |
|---|---|---|
| 기준 26건 재현율 | 26/26 | **26/26** |
| 기준 밖 추가 보고 | 2 | **0** |
| Dependency-Check 오탐 CVE 13건 재등장 | 0 | **0** |

첫 구현의 추가 보고 2건은 2016년 RHEL Tomcat 패키지 권고였습니다. 원인은 두 가지였습니다.
- CPE 버전 `-`(해당 없음)를 "모든 버전"으로 잘못 읽었습니다.
- "Oracle Linux에서 실행될 때"라는 AND 조건을 무시했습니다.

NVD 설정의 AND/OR 논리를 그대로 평가하도록 고치자 0건이 됐습니다. 같은 수정으로 CVE-2018-1258("Spring Security **AND** Spring Framework 5.0.5")도 더 이상 6.2.19에 걸리지 않게 됐습니다. 이전에는 GitHub 검토 데이터 덕분에 우연히 걸러졌을 뿐, 판정 자체는 틀렸었습니다.

### 결과: 경매톡의 OSV 미반영 권고 26건

| 제품 (버전, jar 수) | CVE | 심각도 | 범위 밖 다음 배포 버전 |
|---|---|---|---|
| Spring Framework (6.2.19, 15) | 14 | CRITICAL 3, HIGH 6, MODERATE 4, LOW 1 | 7.0.9 |
| Spring Security (6.5.11, 7) | 5 | CRITICAL 1, HIGH 2, MODERATE 2 | 7.0.7 |
| MySQL Connector/J (9.7.0, 1) | 4 | HIGH 2, MODERATE 2 | 26.7.0 (새 버전 체계) |
| Netty (4.1.137.Final, 17) | 1 | MODERATE 1 | **4.1.138.Final (같은 라인)** |
| Reactor Netty (1.2.18, 2) | 1 | MODERATE 1 | 1.3.7 |
| Spring Data JPA (3.5.13, 1) | 1 | MODERATE 1 | 4.0.7 |

Dependency-Check는 이것을 269쌍으로 보고했고, DepTrace는 같은 내용을 26건으로 보고합니다. 같은 라인의 공개 수정 버전은 Netty 하나뿐이고, 나머지는 Spring Boot 4 이전과 함께 움직여야 합니다.

### 조치: Netty

같은 라인에 공개 수정 버전이 있는 Netty부터 조치했습니다([451744d](https://github.com/gyeongmaetalk/gyeongmaetalk-BE/commit/451744d)).
- BOM 속성 `netty.version`을 4.1.137.Final에서 4.1.138.Final로 올렸습니다. 배포 클래스패스의 Netty 모듈 17개가 모두 4.1.138.Final로 해석됩니다.
- NVD 보완 점검의 OSV 미반영 권고가 26건에서 25건으로 줄었습니다.
- 취약점·라이선스 게이트 결과와 테스트 결과(113개 중 112개 통과)는 이전과 같습니다.

### 자동화

감사 워크플로에 보완 점검 단계를 추가했습니다. 지금은 **보고만** 합니다. 공개 수정 버전이 없는 CRITICAL·HIGH가 남아 있어서, 게이트로 쓰려면 먼저 기능 사용 여부를 확인해 예외 근거를 남기거나 Spring Boot 4로 옮겨야 합니다.

## 후속 과제

- NVD 보완 점검을 게이트로 전환: CRITICAL·HIGH 14건(Spring Framework 9, Spring Security 3, MySQL Connector/J 2)의 기능 사용 여부 확인 후 예외 등록, 또는 Spring Boot 4 이전
- 제품 대응표 확장과, 다른 프로젝트에서 정확도 재측정
- Spring Boot 4 이전 검토 (예외 만료 2027-01-19 전). 미검토 권고 19건(Spring Framework·Security)도 이 이전으로만 공개 수정 가능
- querydsl → OpenFeign 포크(io.github.openfeign.querydsl) 이전
- 운영 설정으로 실제 기동 확인. 이번 점검에서는 저장소에 `application.yml`이 없어 컨텍스트 기동을 검증하지 못했습니다.
- MariaDB Connector/J 전환 검증 (라이선스 예외 만료 2027-05-18 전, 또는 배포 형태가 바뀔 때)
- 약한 카피레프트 7건의 고지 의무 정리 (NOTICE·라이선스 사본 수집)
