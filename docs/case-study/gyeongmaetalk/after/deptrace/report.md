# DepTrace 분석 결과

- 생성: 2026-10-19T17:50:55+09:00
- 기준 구성: `productionRuntimeClasspath` (구성요소 292개)
- 분석 구성: `productionRuntimeClasspath`, `runtimeClasspath`, `testRuntimeClasspath`

## 요약

| 항목 | 값 |
|---|---|
| 취약 구성요소 (전체 구성) | 6 |
| 권고 항목 수 (패키지별 중복 포함) | 8 |
| 취약 구성요소 (배포 클래스패스) | 6 |
| 고유 취약점 (배포 클래스패스, 중복 제거) | 7 |
| 심각도 (고유 취약점 기준) | CRITICAL 3, HIGH 1, MODERATE 3 |

## 수정 지점별 분류 (배포 클래스패스)

| 수정 지점 | 구성요소 수 |
|---|---|
| Spring Boot(BOM) 업그레이드 | 5 |
| 수정 버전 없음 | 1 |

## 구성요소별 상세 (배포 클래스패스)

### org.springframework:spring-webflux:6.2.19 — CRITICAL

- 권고 2건: GHSA-9qf2-26p9-2q2q(CRITICAL), GHSA-j9f9-w8pj-32f8(CRITICAL)
- 버전 결정: Spring Boot BOM(dependency-management 플러그인)이 관리 버전 6.2.19으로 결정
- 유입: 직접 의존성 1개 경로
  - spring-boot-starter-webflux:3.5.16 → spring-webflux:6.2.19
- 수정 버전: 7.0.9 (릴리스 라인 변경 필요)
- 조치: **Spring Boot(BOM) 업그레이드** — Spring Boot BOM이 관리하는 버전이다. 7.0.9 이상을 관리하는 Spring Boot로 올리거나, BOM 버전 속성으로 오버라이드한다(검증된 조합이 깨지므로 근거를 남긴다). 현재 릴리스 라인에는 공개 수정 버전이 없어 7.0.x 라인으로 옮겨야 한다.

### org.springframework:spring-webmvc:6.2.19 — CRITICAL

- 권고 2건: GHSA-j9f9-w8pj-32f8(CRITICAL), GHSA-pc63-qcmh-9cmg(CRITICAL)
- 버전 결정: Spring Boot BOM(dependency-management 플러그인)이 관리 버전 6.2.19으로 결정 (전이 요청: 6.2.19, 6.2.17)
- 유입: 직접 의존성 2개 경로
  - spring-boot-starter-web:3.5.16 → spring-webmvc:6.2.19
  - springdoc-openapi-starter-webmvc-ui:2.8.17 → springdoc-openapi-starter-webmvc-api:2.8.17 → spring-webmvc:6.2.19
- 수정 버전: 7.0.9 (릴리스 라인 변경 필요)
- 조치: **Spring Boot(BOM) 업그레이드** — Spring Boot BOM이 관리하는 버전이다. 7.0.9 이상을 관리하는 Spring Boot로 올리거나, BOM 버전 속성으로 오버라이드한다(검증된 조합이 깨지므로 근거를 남긴다). 현재 릴리스 라인에는 공개 수정 버전이 없어 7.0.x 라인으로 옮겨야 한다.

### com.querydsl:querydsl-jpa:5.0.0 — HIGH

- 권고 1건: GHSA-6q3q-6v5j-h6vg(HIGH)
- 버전 결정: 직접 선언한 버전(5.0.0)이 BOM 관리 버전 5.1.0보다 우선 적용됨
- 유입: 직접 의존성 1개 경로
  - querydsl-jpa:5.0.0
- 수정 버전: 없음 (일부 권고는 수정 버전 없음)
- 다른 좌표의 수정 버전: io.github.openfeign.querydsl:querydsl-jpa:5.6.1, io.github.openfeign.querydsl:querydsl-jpa:6.10.1
- 조치: **수정 버전 없음** — 이 좌표에는 공개된 수정 버전이 없다. 같은 권고가 다른 좌표에는 수정 버전을 두고 있다(io.github.openfeign.querydsl:querydsl-jpa:5.6.1, io.github.openfeign.querydsl:querydsl-jpa:6.10.1): 좌표 이동·포크 여부를 확인한다. 실제 사용 여부를 확인해 제거·대체하거나, 영향이 없다는 근거와 만료일을 남겨 예외로 등록한다.

### io.opentelemetry:opentelemetry-api:1.49.0 — MODERATE

- 권고 1건: GHSA-rcgg-9c38-7xpx(MODERATE)
- 버전 결정: Spring Boot BOM(dependency-management 플러그인)이 관리 버전 1.49.0으로 결정 (전이 요청: 1.62.0) · 요청된 더 높은 버전 대신 낮은 버전이 선택된 하향
- 유입: 직접 의존성 1개 경로
  - firebase-admin:9.11.0 → google-cloud-storage:2.73.0 → opentelemetry-api:1.49.0
- 수정 버전: 1.62.0
- 조치: **Spring Boot(BOM) 업그레이드** — Spring Boot BOM이 관리하는 버전이다. 1.62.0 이상을 관리하는 Spring Boot로 올리거나, BOM 버전 속성으로 오버라이드한다(검증된 조합이 깨지므로 근거를 남긴다).

### org.apache.commons:commons-lang3:3.17.0 — MODERATE

- 권고 1건: GHSA-j288-q9x7-2f5v(MODERATE)
- 버전 결정: Spring Boot BOM(dependency-management 플러그인)이 관리 버전 3.17.0으로 결정 (전이 요청: 3.20.0) · 요청된 더 높은 버전 대신 낮은 버전이 선택된 하향
- 유입: 직접 의존성 1개 경로
  - springdoc-openapi-starter-webmvc-ui:2.8.17 → springdoc-openapi-starter-webmvc-api:2.8.17 → springdoc-openapi-starter-common:2.8.17 → swagger-core-jakarta:2.2.47 → commons-lang3:3.17.0
- 수정 버전: 3.18.0
- 조치: **Spring Boot(BOM) 업그레이드** — Spring Boot BOM이 관리하는 버전이다. 3.18.0 이상을 관리하는 Spring Boot로 올리거나, BOM 버전 속성으로 오버라이드한다(검증된 조합이 깨지므로 근거를 남긴다).

### org.apache.logging.log4j:log4j-api:2.24.3 — MODERATE

- 권고 1건: GHSA-qv9r-c865-cp47(MODERATE)
- 버전 결정: Spring Boot BOM(dependency-management 플러그인)이 관리 버전 2.24.3으로 결정
- 유입: 직접 의존성 9개 경로
  - spring-boot-starter-actuator:3.5.16 → spring-boot-starter:3.5.16 → spring-boot-starter-logging:3.5.16 → log4j-to-slf4j:2.24.3 → log4j-api:2.24.3
  - spring-boot-starter-batch:3.5.16 → spring-boot-starter:3.5.16 → spring-boot-starter-logging:3.5.16 → log4j-to-slf4j:2.24.3 → log4j-api:2.24.3
  - spring-boot-starter-data-jpa:3.5.16 → spring-boot-starter:3.5.16 → spring-boot-starter-logging:3.5.16 → log4j-to-slf4j:2.24.3 → log4j-api:2.24.3
- 수정 버전: 2.25.5
- 조치: **Spring Boot(BOM) 업그레이드** — Spring Boot BOM이 관리하는 버전이다. 2.25.5 이상을 관리하는 Spring Boot로 올리거나, BOM 버전 속성으로 오버라이드한다(검증된 조합이 깨지므로 근거를 남긴다).

