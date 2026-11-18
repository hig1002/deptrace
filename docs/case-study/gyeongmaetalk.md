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

## 후속 과제

- Spring Boot 4 이전 검토 (예외 만료 2027-01-19 전)
- querydsl → OpenFeign 포크(io.github.openfeign.querydsl) 이전
- 운영 설정으로 실제 기동 확인. 이번 점검에서는 저장소에 `application.yml`이 없어 컨텍스트 기동을 검증하지 못했습니다.
- MariaDB Connector/J 전환 검증 (라이선스 예외 만료 2027-05-18 전, 또는 배포 형태가 바뀔 때)
- 약한 카피레프트 7건의 고지 의무 정리 (NOTICE·라이선스 사본 수집)
