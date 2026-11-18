# DepTrace 분석 결과

- 생성: 2026-10-19T17:50:54+09:00
- 기준 구성: `productionRuntimeClasspath` (구성요소 269개)
- 분석 구성: `productionRuntimeClasspath`, `runtimeClasspath`, `testRuntimeClasspath`

## 요약

| 항목 | 값 |
|---|---|
| 취약 구성요소 (전체 구성) | 43 |
| 권고 항목 수 (패키지별 중복 포함) | 165 |
| 취약 구성요소 (배포 클래스패스) | 41 |
| 고유 취약점 (배포 클래스패스, 중복 제거) | 152 |
| 심각도 (고유 취약점 기준) | CRITICAL 13, HIGH 58, MODERATE 64, LOW 17 |

## 수정 지점별 분류 (배포 클래스패스)

| 수정 지점 | 구성요소 수 |
|---|---|
| 직접 선언 버전 상향 | 1 |
| Spring Boot(BOM) 업그레이드 | 34 |
| 전이 의존성 하한 지정 | 4 |
| 수정 버전 없음 | 2 |

## 구성요소별 상세 (배포 클래스패스)

### io.netty:netty-handler:4.1.114.Final — CRITICAL

- 권고 6건: GHSA-c4c3-7fpv-j4q5(CRITICAL), GHSA-3qp7-7mw8-wx86(HIGH), GHSA-4g8c-wm8x-jfhw(HIGH), GHSA-c653-97m9-rcg9(HIGH), GHSA-x4gw-5cx5-pgmh(HIGH), GHSA-fccg-mwvh-qqg4(MODERATE)
- 버전 결정: Spring Boot BOM(dependency-management 플러그인)이 관리 버전 4.1.114.Final으로 결정 (전이 요청: 4.1.84.Final, 4.1.107.Final, 4.1.86.Final, 4.1.114.Final)
- 유입: 직접 의존성 4개 경로
  - firebase-admin:9.1.1 → netty-handler:4.1.114.Final
  - spring-boot-starter-data-redis:3.3.5 → lettuce-core:6.3.2.RELEASE → netty-handler:4.1.114.Final
  - s3:2.20.20 → netty-nio-client:2.20.20 → netty-handler:4.1.114.Final
- 수정 버전: 4.1.137.Final
- 조치: **Spring Boot(BOM) 업그레이드** — Spring Boot BOM이 관리하는 버전이다. 4.1.137.Final 이상을 관리하는 Spring Boot로 올리거나, BOM 버전 속성으로 오버라이드한다(검증된 조합이 깨지므로 근거를 남긴다).

### org.apache.tomcat.embed:tomcat-embed-core:10.1.31 — CRITICAL

- 권고 32건: GHSA-5m62-pw8w-7w9f(CRITICAL), GHSA-83qj-6fr2-vhqg(CRITICAL), GHSA-9xv2-5v5q-p794(CRITICAL), GHSA-gcx9-497g-6cp6(CRITICAL), GHSA-h3x4-894j-xpx5(CRITICAL), GHSA-h6fc-48rj-7qqh(CRITICAL) 외
- 버전 결정: Spring Boot BOM(dependency-management 플러그인)이 관리 버전 10.1.31으로 결정
- 유입: 직접 의존성 1개 경로
  - spring-boot-starter-web:3.3.5 → spring-boot-starter-tomcat:3.3.5 → tomcat-embed-core:10.1.31
- 수정 버전: 10.1.58 → 실제 배포된 버전 10.1.59
- 조치: **Spring Boot(BOM) 업그레이드** — Spring Boot BOM이 관리하는 버전이다. 10.1.59 이상을 관리하는 Spring Boot로 올리거나, BOM 버전 속성으로 오버라이드한다(검증된 조합이 깨지므로 근거를 남긴다). OSV 수정 버전 10.1.58은 Maven Central에 배포되지 않아 10.1.59을 기준으로 한다.

### org.bouncycastle:bcprov-jdk18on:1.83 — CRITICAL

- 권고 5건: GHSA-574f-3g2m-x479(CRITICAL), GHSA-9pwp-9qqc-pr26(CRITICAL), GHSA-p93r-85wp-75v3(HIGH), GHSA-qp49-qgx5-5m26(HIGH), GHSA-c3fc-8qff-9hwx(MODERATE)
- 버전 결정: 전이 의존성이 요청한 버전 그대로 선택됨
- 유입: 직접 의존성 1개 경로
  - app-store-server-library:5.0.0 → bcprov-jdk18on:1.83
- 수정 버전: 1.85
- 조치: **전이 의존성 하한 지정** — 전이 의존성이다. 유입자(com.apple.itunes.storekit:app-store-server-library:5.0.0)를 올리거나, constraints { implementation('org.bouncycastle:bcprov-jdk18on:1.85') } 로 하한을 지정한다.

### org.springframework.security:spring-security-web:6.3.4 — CRITICAL

- 권고 3건: GHSA-mf92-479x-3373(CRITICAL), GHSA-293q-567p-wmwq(MODERATE), GHSA-x2r2-rvhq-2mqv(MODERATE)
- 버전 결정: Spring Boot BOM(dependency-management 플러그인)이 관리 버전 6.3.4으로 결정
- 유입: 직접 의존성 2개 경로
  - spring-boot-starter-security:3.3.5 → spring-security-web:6.3.4
  - spring-boot-starter-oauth2-client:3.3.5 → spring-security-oauth2-client:6.3.4 → spring-security-web:6.3.4
- 수정 버전: 6.5.11 (릴리스 라인 변경 필요)
- 조치: **Spring Boot(BOM) 업그레이드** — Spring Boot BOM이 관리하는 버전이다. 6.5.11 이상을 관리하는 Spring Boot로 올리거나, BOM 버전 속성으로 오버라이드한다(검증된 조합이 깨지므로 근거를 남긴다). 현재 릴리스 라인에는 공개 수정 버전이 없어 6.5.x 라인으로 옮겨야 한다.

### org.springframework:spring-webflux:6.1.14 — CRITICAL

- 권고 13건: GHSA-9qf2-26p9-2q2q(CRITICAL), GHSA-x23c-287f-qqv5(HIGH), GHSA-4773-3jfm-qmx3(MODERATE), GHSA-4hfh-6x8g-gwpp(MODERATE), GHSA-5843-p793-ghmm(MODERATE), GHSA-6p4f-wcwh-5vvm(MODERATE) 외
- 버전 결정: Spring Boot BOM(dependency-management 플러그인)이 관리 버전 6.1.14으로 결정
- 유입: 직접 의존성 1개 경로
  - spring-boot-starter-webflux:3.3.5 → spring-webflux:6.1.14
- 수정 버전: 7.0.9 (릴리스 라인 변경 필요)
- 조치: **Spring Boot(BOM) 업그레이드** — Spring Boot BOM이 관리하는 버전이다. 7.0.9 이상을 관리하는 Spring Boot로 올리거나, BOM 버전 속성으로 오버라이드한다(검증된 조합이 깨지므로 근거를 남긴다). 현재 릴리스 라인에는 공개 수정 버전이 없어 7.0.x 라인으로 옮겨야 한다.

### org.springframework:spring-webmvc:6.1.14 — CRITICAL

- 권고 13건: GHSA-pc63-qcmh-9cmg(CRITICAL), GHSA-3chg-m5w7-qfv5(HIGH), GHSA-x23c-287f-qqv5(HIGH), GHSA-4773-3jfm-qmx3(MODERATE), GHSA-6p4f-wcwh-5vvm(MODERATE), GHSA-72pg-x5f8-j25j(MODERATE) 외
- 버전 결정: Spring Boot BOM(dependency-management 플러그인)이 관리 버전 6.1.14으로 결정 (전이 요청: 6.1.14, 6.0.11)
- 유입: 직접 의존성 2개 경로
  - spring-boot-starter-web:3.3.5 → spring-webmvc:6.1.14
  - springdoc-openapi-starter-webmvc-ui:2.2.0 → springdoc-openapi-starter-webmvc-api:2.2.0 → spring-webmvc:6.1.14
- 수정 버전: 7.0.9 (릴리스 라인 변경 필요)
- 조치: **Spring Boot(BOM) 업그레이드** — Spring Boot BOM이 관리하는 버전이다. 7.0.9 이상을 관리하는 Spring Boot로 올리거나, BOM 버전 속성으로 오버라이드한다(검증된 조합이 깨지므로 근거를 남긴다). 현재 릴리스 라인에는 공개 수정 버전이 없어 7.0.x 라인으로 옮겨야 한다.

### com.amazonaws:aws-java-sdk-s3:1.11.792 — HIGH

- 권고 1건: GHSA-c28r-hw5m-5gv3(HIGH)
- 버전 결정: 전이 의존성이 요청한 버전 그대로 선택됨
- 유입: 직접 의존성 1개 경로
  - spring-cloud-starter-aws:2.2.6.RELEASE → spring-cloud-aws-context:2.2.6.RELEASE → spring-cloud-aws-core:2.2.6.RELEASE → aws-java-sdk-s3:1.11.792
- 수정 버전: 1.12.261
- 조치: **전이 의존성 하한 지정** — 전이 의존성이다. 유입자(org.springframework.cloud:spring-cloud-starter-aws:2.2.6.RELEASE)를 올리거나, constraints { implementation('com.amazonaws:aws-java-sdk-s3:1.12.261') } 로 하한을 지정한다.

### com.fasterxml.jackson.core:jackson-core:2.17.2 — HIGH

- 권고 4건: GHSA-7hhh-6rmp-j9qf(HIGH), GHSA-p6pp-m3f8-5c89(HIGH), GHSA-r7wm-3cxj-wff9(HIGH), GHSA-72hv-8253-57qq(MODERATE)
- 버전 결정: Spring Boot BOM(dependency-management 플러그인)이 관리 버전 2.17.2으로 결정 (전이 요청: 2.17.2, 2.13.4)
- 유입: 직접 의존성 9개 경로
  - app-store-server-library:5.0.0 → jackson-databind:2.17.2 → jackson-core:2.17.2
  - java-jwt:4.4.0 → jackson-databind:2.17.2 → jackson-core:2.17.2
  - firebase-admin:9.1.1 → google-cloud-storage:2.14.0 → jackson-core:2.17.2
- 수정 버전: 2.18.11
- 조치: **Spring Boot(BOM) 업그레이드** — Spring Boot BOM이 관리하는 버전이다. 2.18.11 이상을 관리하는 Spring Boot로 올리거나, BOM 버전 속성으로 오버라이드한다(검증된 조합이 깨지므로 근거를 남긴다).

### com.fasterxml.jackson.core:jackson-databind:2.17.2 — HIGH

- 권고 11건: GHSA-cxp5-3px4-pw24(HIGH), GHSA-j3rv-43j4-c7qm(HIGH), GHSA-q4xh-88c3-wmh7(HIGH), GHSA-rmj7-2vxq-3g9f(HIGH), GHSA-wv8q-qhhj-9h54(HIGH), GHSA-3pjw-73gf-8qr5(MODERATE) 외
- 버전 결정: Spring Boot BOM(dependency-management 플러그인)이 관리 버전 2.17.2으로 결정 (전이 요청: 2.12.6.1, 2.14.2, 2.16.1, 2.17.2, 2.15.1, 2.6.7.3)
- 유입: 직접 의존성 8개 경로
  - app-store-server-library:5.0.0 → jackson-databind:2.17.2
  - java-jwt:4.4.0 → jackson-databind:2.17.2
  - jjwt-jackson:0.11.5 → jackson-databind:2.17.2
- 수정 버전: 2.18.11
- 조치: **Spring Boot(BOM) 업그레이드** — Spring Boot BOM이 관리하는 버전이다. 2.18.11 이상을 관리하는 Spring Boot로 올리거나, BOM 버전 속성으로 오버라이드한다(검증된 조합이 깨지므로 근거를 남긴다).

### com.google.protobuf:protobuf-java:3.25.1 — HIGH

- 권고 1건: GHSA-735f-pc8j-v9w8(HIGH)
- 버전 결정: 버전 충돌 중 가장 높은 버전 선택 (between versions 3.25.1 and 3.21.8)
- 유입: 직접 의존성 2개 경로
  - mysql-connector-j:8.3.0 → protobuf-java:3.25.1
  - firebase-admin:9.1.1 → google-cloud-storage:2.14.0 → protobuf-java:3.25.1
- 수정 버전: 3.25.5
- 조치: **전이 의존성 하한 지정** — 전이 의존성이다. 유입자(com.mysql:mysql-connector-j:8.3.0, com.google.firebase:firebase-admin:9.1.1)를 올리거나, constraints { implementation('com.google.protobuf:protobuf-java:3.25.5') } 로 하한을 지정한다.

### com.nimbusds:nimbus-jose-jwt:9.37 — HIGH

- 권고 2건: GHSA-gvpg-vgmx-xg6w(HIGH), GHSA-xwmg-2g98-w7v9(MODERATE)
- 버전 결정: 직접 선언한 버전(9.37)이 다른 라이브러리의 요청 9.37.3보다 우선 적용됨 · 요청된 더 높은 버전 대신 낮은 버전이 선택된 하향
- 유입: 직접 의존성 2개 경로
  - nimbus-jose-jwt:9.37
  - spring-boot-starter-oauth2-client:3.3.5 → spring-security-oauth2-jose:6.3.4 → nimbus-jose-jwt:9.37
- 수정 버전: 9.37.4
- 조치: **직접 선언 버전 상향** — 직접 선언 버전을 9.37.4 이상으로 올린다. 직접 선언을 제거하면 9.37.3이 선택되지만 9.37.4 미만이라 일부 권고가 남는다.

### com.querydsl:querydsl-jpa:5.0.0 — HIGH

- 권고 1건: GHSA-6q3q-6v5j-h6vg(HIGH)
- 버전 결정: 직접 선언한 버전(5.0.0)이 BOM 관리 버전 5.1.0보다 우선 적용됨
- 유입: 직접 의존성 1개 경로
  - querydsl-jpa:5.0.0
- 수정 버전: 없음 (일부 권고는 수정 버전 없음)
- 다른 좌표의 수정 버전: io.github.openfeign.querydsl:querydsl-jpa:5.6.1, io.github.openfeign.querydsl:querydsl-jpa:6.10.1
- 조치: **수정 버전 없음** — 이 좌표에는 공개된 수정 버전이 없다. 같은 권고가 다른 좌표에는 수정 버전을 두고 있다(io.github.openfeign.querydsl:querydsl-jpa:5.6.1, io.github.openfeign.querydsl:querydsl-jpa:6.10.1): 좌표 이동·포크 여부를 확인한다. 실제 사용 여부를 확인해 제거·대체하거나, 영향이 없다는 근거와 만료일을 남겨 예외로 등록한다.

### io.grpc:grpc-netty-shaded:1.50.1 — HIGH

- 권고 1건: GHSA-prj3-ccx8-p6x4(HIGH)
- 버전 결정: 전이 의존성이 요청한 버전 그대로 선택됨
- 유입: 직접 의존성 1개 경로
  - firebase-admin:9.1.1 → google-cloud-storage:2.14.0 → grpc-netty-shaded:1.50.1
- 수정 버전: 1.75.0
- 조치: **전이 의존성 하한 지정** — 전이 의존성이다. 유입자(com.google.firebase:firebase-admin:9.1.1)를 올리거나, constraints { implementation('io.grpc:grpc-netty-shaded:1.75.0') } 로 하한을 지정한다.

### io.micrometer:micrometer-core:1.13.6 — HIGH

- 권고 1건: GHSA-g3pr-3p32-fp23(HIGH)
- 버전 결정: Spring Boot BOM(dependency-management 플러그인)이 관리 버전 1.13.6으로 결정 (전이 요청: 1.13.6, 1.12.6)
- 유입: 직접 의존성 3개 경로
  - micrometer-registry-prometheus:1.13.6 → micrometer-core:1.13.6
  - spring-boot-starter-actuator:3.3.5 → micrometer-jakarta9:1.13.6 → micrometer-core:1.13.6
  - spring-boot-starter-batch:3.3.5 → spring-batch-core:5.1.2 → micrometer-core:1.13.6
- 수정 버전: 1.15.12 (릴리스 라인 변경 필요)
- 조치: **Spring Boot(BOM) 업그레이드** — Spring Boot BOM이 관리하는 버전이다. 1.15.12 이상을 관리하는 Spring Boot로 올리거나, BOM 버전 속성으로 오버라이드한다(검증된 조합이 깨지므로 근거를 남긴다). 현재 릴리스 라인에는 공개 수정 버전이 없어 1.15.x 라인으로 옮겨야 한다.

### io.netty:netty-codec:4.1.114.Final — HIGH

- 권고 3건: GHSA-558v-64gr-wgg4(HIGH), GHSA-mj4r-2hfc-f8p6(HIGH), GHSA-3p8m-j85q-pgmj(MODERATE)
- 버전 결정: Spring Boot BOM(dependency-management 플러그인)이 관리 버전 4.1.114.Final으로 결정 (전이 요청: 4.1.86.Final, 4.1.114.Final)
- 유입: 직접 의존성 4개 경로
  - firebase-admin:9.1.1 → netty-codec-http:4.1.114.Final → netty-codec:4.1.114.Final
  - s3:2.20.20 → netty-nio-client:2.20.20 → netty-codec:4.1.114.Final
  - spring-boot-starter-data-redis:3.3.5 → lettuce-core:6.3.2.RELEASE → netty-handler:4.1.114.Final → netty-codec:4.1.114.Final
- 수정 버전: 4.1.136.Final
- 조치: **Spring Boot(BOM) 업그레이드** — Spring Boot BOM이 관리하는 버전이다. 4.1.136.Final 이상을 관리하는 Spring Boot로 올리거나, BOM 버전 속성으로 오버라이드한다(검증된 조합이 깨지므로 근거를 남긴다).

### io.netty:netty-codec-dns:4.1.114.Final — HIGH

- 권고 2건: GHSA-cm33-6792-r9fm(HIGH), GHSA-mfg7-5gfp-c4w3(MODERATE)
- 버전 결정: Spring Boot BOM(dependency-management 플러그인)이 관리 버전 4.1.114.Final으로 결정
- 유입: 직접 의존성 1개 경로
  - spring-boot-starter-webflux:3.3.5 → spring-boot-starter-reactor-netty:3.3.5 → reactor-netty-http:1.1.23 → netty-resolver-dns:4.1.114.Final → netty-codec-dns:4.1.114.Final
- 수정 버전: 4.1.136.Final
- 조치: **Spring Boot(BOM) 업그레이드** — Spring Boot BOM이 관리하는 버전이다. 4.1.136.Final 이상을 관리하는 Spring Boot로 올리거나, BOM 버전 속성으로 오버라이드한다(검증된 조합이 깨지므로 근거를 남긴다).

### io.netty:netty-codec-http:4.1.114.Final — HIGH

- 권고 18건: GHSA-57rv-r2g8-2cj3(HIGH), GHSA-6jqx-86gh-f27w(HIGH), GHSA-f6hv-jmp6-3vwv(HIGH), GHSA-jppx-w49h-x2qq(HIGH), GHSA-mvh2-crg5-v77c(HIGH), GHSA-pwqr-wmgm-9rr8(HIGH) 외
- 버전 결정: Spring Boot BOM(dependency-management 플러그인)이 관리 버전 4.1.114.Final으로 결정 (전이 요청: 4.1.84.Final, 4.1.86.Final, 4.1.114.Final)
- 유입: 직접 의존성 3개 경로
  - firebase-admin:9.1.1 → netty-codec-http:4.1.114.Final
  - s3:2.20.20 → netty-nio-client:2.20.20 → netty-codec-http:4.1.114.Final
  - spring-boot-starter-webflux:3.3.5 → spring-boot-starter-reactor-netty:3.3.5 → reactor-netty-http:1.1.23 → netty-codec-http:4.1.114.Final
- 수정 버전: 4.1.137.Final
- 조치: **Spring Boot(BOM) 업그레이드** — Spring Boot BOM이 관리하는 버전이다. 4.1.137.Final 이상을 관리하는 Spring Boot로 올리거나, BOM 버전 속성으로 오버라이드한다(검증된 조합이 깨지므로 근거를 남긴다).

### io.netty:netty-codec-http2:4.1.114.Final — HIGH

- 권고 8건: GHSA-93wv-jw9v-4972(HIGH), GHSA-f6hv-jmp6-3vwv(HIGH), GHSA-prj3-ccx8-p6x4(HIGH), GHSA-w9fj-cfpg-grvv(HIGH), GHSA-563q-j3cm-6jxm(MODERATE), GHSA-5x3r-wrvg-rp6q(MODERATE) 외
- 버전 결정: Spring Boot BOM(dependency-management 플러그인)이 관리 버전 4.1.114.Final으로 결정 (전이 요청: 4.1.86.Final, 4.1.114.Final)
- 유입: 직접 의존성 2개 경로
  - s3:2.20.20 → netty-nio-client:2.20.20 → netty-codec-http2:4.1.114.Final
  - spring-boot-starter-webflux:3.3.5 → spring-boot-starter-reactor-netty:3.3.5 → reactor-netty-http:1.1.23 → netty-codec-http2:4.1.114.Final
- 수정 버전: 4.1.136.Final
- 조치: **Spring Boot(BOM) 업그레이드** — Spring Boot BOM이 관리하는 버전이다. 4.1.136.Final 이상을 관리하는 Spring Boot로 올리거나, BOM 버전 속성으로 오버라이드한다(검증된 조합이 깨지므로 근거를 남긴다).

### io.netty:netty-resolver-dns:4.1.114.Final — HIGH

- 권고 3건: GHSA-5pvg-856g-cp85(HIGH), GHSA-676x-f7gg-47vc(HIGH), GHSA-xmv7-r254-6q78(MODERATE)
- 버전 결정: Spring Boot BOM(dependency-management 플러그인)이 관리 버전 4.1.114.Final으로 결정
- 유입: 직접 의존성 1개 경로
  - spring-boot-starter-webflux:3.3.5 → spring-boot-starter-reactor-netty:3.3.5 → reactor-netty-http:1.1.23 → netty-resolver-dns:4.1.114.Final
- 수정 버전: 4.1.135.Final
- 조치: **Spring Boot(BOM) 업그레이드** — Spring Boot BOM이 관리하는 버전이다. 4.1.135.Final 이상을 관리하는 Spring Boot로 올리거나, BOM 버전 속성으로 오버라이드한다(검증된 조합이 깨지므로 근거를 남긴다).

### net.minidev:json-smart:2.5.1 — HIGH

- 권고 1건: GHSA-pq2g-wx69-c263(HIGH)
- 버전 결정: Spring Boot BOM(dependency-management 플러그인)이 관리 버전 2.5.1으로 결정 · 요청 범위 [1.3.3,2.4.10] 밖의 버전
- 유입: 직접 의존성 1개 경로
  - spring-boot-starter-oauth2-client:3.3.5 → spring-security-oauth2-client:6.3.4 → oauth2-oidc-sdk:9.43.4 → json-smart:2.5.1
- 수정 버전: 2.5.2
- 조치: **Spring Boot(BOM) 업그레이드** — Spring Boot BOM이 관리하는 버전이다. 2.5.2 이상을 관리하는 Spring Boot로 올리거나, BOM 버전 속성으로 오버라이드한다(검증된 조합이 깨지므로 근거를 남긴다).

### org.springframework.boot:spring-boot:3.3.5 — HIGH

- 권고 2건: GHSA-rc42-6c7j-7h5r(HIGH), GHSA-wwpq-f5c3-7hvx(HIGH)
- 버전 결정: Spring Boot BOM(dependency-management 플러그인)이 관리 버전 3.3.5으로 결정
- 유입: 직접 의존성 10개 경로
  - spring-boot-starter-actuator:3.3.5 → spring-boot-starter:3.3.5 → spring-boot:3.3.5
  - spring-boot-starter-batch:3.3.5 → spring-boot-starter:3.3.5 → spring-boot:3.3.5
  - spring-boot-starter-data-redis:3.3.5 → spring-boot-starter:3.3.5 → spring-boot:3.3.5
- 수정 버전: 3.5.14 (릴리스 라인 변경 필요)
- 조치: **Spring Boot(BOM) 업그레이드** — Spring Boot BOM이 관리하는 버전이다. 3.5.14 이상을 관리하는 Spring Boot로 올리거나, BOM 버전 속성으로 오버라이드한다(검증된 조합이 깨지므로 근거를 남긴다). 현재 릴리스 라인에는 공개 수정 버전이 없어 3.5.x 라인으로 옮겨야 한다.

### org.springframework.boot:spring-boot-starter-actuator:3.3.5 — HIGH

- 권고 1건: GHSA-mgvc-8q2h-5pgc(HIGH)
- 버전 결정: Spring Boot BOM(dependency-management 플러그인)이 관리 버전 3.3.5으로 결정
- 유입: 직접 의존성 1개 경로
  - spring-boot-starter-actuator:3.3.5
- 수정 버전: 3.5.12 (릴리스 라인 변경 필요)
- 조치: **Spring Boot(BOM) 업그레이드** — Spring Boot BOM이 관리하는 버전이다. 3.5.12 이상을 관리하는 Spring Boot로 올리거나, BOM 버전 속성으로 오버라이드한다(검증된 조합이 깨지므로 근거를 남긴다). 현재 릴리스 라인에는 공개 수정 버전이 없어 3.5.x 라인으로 옮겨야 한다.

### org.springframework.data:spring-data-commons:3.3.5 — HIGH

- 권고 3건: GHSA-9fw2-h3hf-293r(HIGH), GHSA-5m4m-73w9-8433(MODERATE), GHSA-5vpf-xvv7-c8vh(MODERATE)
- 버전 결정: Spring Boot BOM(dependency-management 플러그인)이 관리 버전 3.3.5으로 결정
- 유입: 직접 의존성 2개 경로
  - spring-boot-starter-data-jpa:3.3.5 → spring-data-jpa:3.3.5 → spring-data-commons:3.3.5
  - spring-boot-starter-data-redis:3.3.5 → spring-data-redis:3.3.5 → spring-data-keyvalue:3.3.5 → spring-data-commons:3.3.5
- 수정 버전: 3.5.12 (릴리스 라인 변경 필요)
- 조치: **Spring Boot(BOM) 업그레이드** — Spring Boot BOM이 관리하는 버전이다. 3.5.12 이상을 관리하는 Spring Boot로 올리거나, BOM 버전 속성으로 오버라이드한다(검증된 조합이 깨지므로 근거를 남긴다). 현재 릴리스 라인에는 공개 수정 버전이 없어 3.5.x 라인으로 옮겨야 한다.

### org.springframework.security:spring-security-crypto:6.3.4 — HIGH

- 권고 1건: GHSA-mg83-c7gq-rv5c(HIGH)
- 버전 결정: Spring Boot BOM(dependency-management 플러그인)이 관리 버전 6.3.4으로 결정
- 유입: 직접 의존성 2개 경로
  - spring-boot-starter-oauth2-client:3.3.5 → spring-security-core:6.3.4 → spring-security-crypto:6.3.4
  - spring-boot-starter-security:3.3.5 → spring-security-config:6.3.4 → spring-security-core:6.3.4 → spring-security-crypto:6.3.4
- 수정 버전: 6.3.8
- 조치: **Spring Boot(BOM) 업그레이드** — Spring Boot BOM이 관리하는 버전이다. 6.3.8 이상을 관리하는 Spring Boot로 올리거나, BOM 버전 속성으로 오버라이드한다(검증된 조합이 깨지므로 근거를 남긴다).

### org.springframework:spring-core:6.1.14 — HIGH

- 권고 2건: GHSA-jmp9-x22r-554x(HIGH), GHSA-659m-px2c-25wj(LOW)
- 버전 결정: Spring Boot BOM(dependency-management 플러그인)이 관리 버전 6.1.14으로 결정 (전이 요청: 6.1.14, 6.1.7)
- 유입: 직접 의존성 10개 경로
  - spring-boot-starter-actuator:3.3.5 → spring-boot-starter:3.3.5 → spring-core:6.1.14
  - spring-boot-starter-batch:3.3.5 → spring-boot-starter:3.3.5 → spring-core:6.1.14
  - spring-boot-starter-data-jpa:3.3.5 → spring-data-jpa:3.3.5 → spring-core:6.1.14
- 수정 버전: 6.2.19 (릴리스 라인 변경 필요)
- 조치: **Spring Boot(BOM) 업그레이드** — Spring Boot BOM이 관리하는 버전이다. 6.2.19 이상을 관리하는 Spring Boot로 올리거나, BOM 버전 속성으로 오버라이드한다(검증된 조합이 깨지므로 근거를 남긴다). 현재 릴리스 라인에는 공개 수정 버전이 없어 6.2.x 라인으로 옮겨야 한다.

### org.springframework:spring-expression:6.1.14 — HIGH

- 권고 3건: GHSA-r5w3-xv2f-j59q(HIGH), GHSA-wxpp-56q6-5pcg(MODERATE), GHSA-9f52-rjqv-25qv(LOW)
- 버전 결정: Spring Boot BOM(dependency-management 플러그인)이 관리 버전 6.1.14으로 결정
- 유입: 직접 의존성 10개 경로
  - spring-boot-starter-oauth2-client:3.3.5 → spring-security-core:6.3.4 → spring-expression:6.1.14
  - spring-boot-starter-security:3.3.5 → spring-security-web:6.3.4 → spring-expression:6.1.14
  - spring-boot-starter-web:3.3.5 → spring-webmvc:6.1.14 → spring-expression:6.1.14
- 수정 버전: 6.2.19 (릴리스 라인 변경 필요)
- 조치: **Spring Boot(BOM) 업그레이드** — Spring Boot BOM이 관리하는 버전이다. 6.2.19 이상을 관리하는 Spring Boot로 올리거나, BOM 버전 속성으로 오버라이드한다(검증된 조합이 깨지므로 근거를 남긴다). 현재 릴리스 라인에는 공개 수정 버전이 없어 6.2.x 라인으로 옮겨야 한다.

### software.amazon.ion:ion-java:1.0.2 — HIGH

- 권고 1건: GHSA-264p-99wq-f4j6(HIGH)
- 버전 결정: 전이 의존성이 요청한 버전 그대로 선택됨
- 유입: 직접 의존성 1개 경로
  - spring-cloud-starter-aws:2.2.6.RELEASE → spring-cloud-aws-context:2.2.6.RELEASE → spring-cloud-aws-core:2.2.6.RELEASE → aws-java-sdk-core:1.11.792 → ion-java:1.0.2
- 수정 버전: 없음 (일부 권고는 수정 버전 없음)
- 다른 좌표의 수정 버전: com.amazon.ion:ion-java:1.10.5
- 조치: **수정 버전 없음** — 이 좌표에는 공개된 수정 버전이 없다. 같은 권고가 다른 좌표에는 수정 버전을 두고 있다(com.amazon.ion:ion-java:1.10.5): 좌표 이동·포크 여부를 확인한다. 실제 사용 여부를 확인해 제거·대체하거나, 영향이 없다는 근거와 만료일을 남겨 예외로 등록한다.

### ch.qos.logback:logback-core:1.5.11 — MODERATE

- 권고 6건: GHSA-25qh-j22f-pwp8(MODERATE), GHSA-pr98-23f8-jwxv(MODERATE), GHSA-6v67-2wr5-gvf4(LOW), GHSA-jhq6-gfmj-v8fx(LOW), GHSA-p47f-322f-whfh(LOW), GHSA-qqpg-mvqg-649v(LOW)
- 버전 결정: Spring Boot BOM(dependency-management 플러그인)이 관리 버전 1.5.11으로 결정
- 유입: 직접 의존성 8개 경로
  - spring-boot-starter-actuator:3.3.5 → spring-boot-starter:3.3.5 → spring-boot-starter-logging:3.3.5 → logback-classic:1.5.11 → logback-core:1.5.11
  - spring-boot-starter-batch:3.3.5 → spring-boot-starter:3.3.5 → spring-boot-starter-logging:3.3.5 → logback-classic:1.5.11 → logback-core:1.5.11
  - spring-boot-starter-data-redis:3.3.5 → spring-boot-starter:3.3.5 → spring-boot-starter-logging:3.3.5 → logback-classic:1.5.11 → logback-core:1.5.11
- 수정 버전: 1.5.34
- 조치: **Spring Boot(BOM) 업그레이드** — Spring Boot BOM이 관리하는 버전이다. 1.5.34 이상을 관리하는 Spring Boot로 올리거나, BOM 버전 속성으로 오버라이드한다(검증된 조합이 깨지므로 근거를 남긴다).

### io.netty:netty-common:4.1.114.Final — MODERATE

- 권고 2건: GHSA-389x-839f-4rhx(MODERATE), GHSA-xq3w-v528-46rv(MODERATE)
- 버전 결정: Spring Boot BOM(dependency-management 플러그인)이 관리 버전 4.1.114.Final으로 결정 (전이 요청: 4.1.107.Final, 4.1.86.Final, 4.1.114.Final)
- 유입: 직접 의존성 4개 경로
  - firebase-admin:9.1.1 → netty-codec-http:4.1.114.Final → netty-common:4.1.114.Final
  - spring-boot-starter-data-redis:3.3.5 → lettuce-core:6.3.2.RELEASE → netty-common:4.1.114.Final
  - s3:2.20.20 → netty-nio-client:2.20.20 → netty-common:4.1.114.Final
- 수정 버전: 4.1.118.Final
- 조치: **Spring Boot(BOM) 업그레이드** — Spring Boot BOM이 관리하는 버전이다. 4.1.118.Final 이상을 관리하는 Spring Boot로 올리거나, BOM 버전 속성으로 오버라이드한다(검증된 조합이 깨지므로 근거를 남긴다).

### io.netty:netty-transport-native-epoll:4.1.114.Final — MODERATE

- 권고 1건: GHSA-w573-9ffj-6ff9(MODERATE)
- 버전 결정: Spring Boot BOM(dependency-management 플러그인)이 관리 버전 4.1.114.Final으로 결정
- 유입: 직접 의존성 1개 경로
  - spring-boot-starter-webflux:3.3.5 → spring-boot-starter-reactor-netty:3.3.5 → reactor-netty-http:1.1.23 → netty-transport-native-epoll:4.1.114.Final
- 수정 버전: 4.1.135.Final
- 조치: **Spring Boot(BOM) 업그레이드** — Spring Boot BOM이 관리하는 버전이다. 4.1.135.Final 이상을 관리하는 Spring Boot로 올리거나, BOM 버전 속성으로 오버라이드한다(검증된 조합이 깨지므로 근거를 남긴다).

### io.projectreactor.netty:reactor-netty-http:1.1.23 — MODERATE

- 권고 1건: GHSA-4q2v-9p7v-3v22(MODERATE)
- 버전 결정: Spring Boot BOM(dependency-management 플러그인)이 관리 버전 1.1.23으로 결정
- 유입: 직접 의존성 1개 경로
  - spring-boot-starter-webflux:3.3.5 → spring-boot-starter-reactor-netty:3.3.5 → reactor-netty-http:1.1.23
- 수정 버전: 1.2.8
- 조치: **Spring Boot(BOM) 업그레이드** — Spring Boot BOM이 관리하는 버전이다. 1.2.8 이상을 관리하는 Spring Boot로 올리거나, BOM 버전 속성으로 오버라이드한다(검증된 조합이 깨지므로 근거를 남긴다).

### org.apache.commons:commons-lang3:3.14.0 — MODERATE

- 권고 1건: GHSA-j288-q9x7-2f5v(MODERATE)
- 버전 결정: Spring Boot BOM(dependency-management 플러그인)이 관리 버전 3.14.0으로 결정 (전이 요청: 3.12.0)
- 유입: 직접 의존성 1개 경로
  - springdoc-openapi-starter-webmvc-ui:2.2.0 → springdoc-openapi-starter-webmvc-api:2.2.0 → springdoc-openapi-starter-common:2.2.0 → swagger-core-jakarta:2.2.15 → commons-lang3:3.14.0
- 수정 버전: 3.18.0
- 조치: **Spring Boot(BOM) 업그레이드** — Spring Boot BOM이 관리하는 버전이다. 3.18.0 이상을 관리하는 Spring Boot로 올리거나, BOM 버전 속성으로 오버라이드한다(검증된 조합이 깨지므로 근거를 남긴다).

### org.apache.logging.log4j:log4j-api:2.23.1 — MODERATE

- 권고 1건: GHSA-qv9r-c865-cp47(MODERATE)
- 버전 결정: Spring Boot BOM(dependency-management 플러그인)이 관리 버전 2.23.1으로 결정
- 유입: 직접 의존성 8개 경로
  - spring-boot-starter-actuator:3.3.5 → spring-boot-starter:3.3.5 → spring-boot-starter-logging:3.3.5 → log4j-to-slf4j:2.23.1 → log4j-api:2.23.1
  - spring-boot-starter-batch:3.3.5 → spring-boot-starter:3.3.5 → spring-boot-starter-logging:3.3.5 → log4j-to-slf4j:2.23.1 → log4j-api:2.23.1
  - spring-boot-starter-data-redis:3.3.5 → spring-boot-starter:3.3.5 → spring-boot-starter-logging:3.3.5 → log4j-to-slf4j:2.23.1 → log4j-api:2.23.1
- 수정 버전: 2.25.5
- 조치: **Spring Boot(BOM) 업그레이드** — Spring Boot BOM이 관리하는 버전이다. 2.25.5 이상을 관리하는 Spring Boot로 올리거나, BOM 버전 속성으로 오버라이드한다(검증된 조합이 깨지므로 근거를 남긴다).

### org.springframework.boot:spring-boot-autoconfigure:3.3.5 — MODERATE

- 권고 1건: GHSA-ggg2-9786-hwc8(MODERATE)
- 버전 결정: Spring Boot BOM(dependency-management 플러그인)이 관리 버전 3.3.5으로 결정 (전이 요청: 3.3.5, 2.3.8.RELEASE, 3.1.2)
- 유입: 직접 의존성 10개 경로
  - spring-boot-starter-actuator:3.3.5 → spring-boot-starter:3.3.5 → spring-boot-autoconfigure:3.3.5
  - spring-boot-starter-batch:3.3.5 → spring-boot-starter:3.3.5 → spring-boot-autoconfigure:3.3.5
  - spring-boot-starter-data-redis:3.3.5 → spring-boot-starter:3.3.5 → spring-boot-autoconfigure:3.3.5
- 수정 버전: 3.5.15 (릴리스 라인 변경 필요)
- 조치: **Spring Boot(BOM) 업그레이드** — Spring Boot BOM이 관리하는 버전이다. 3.5.15 이상을 관리하는 Spring Boot로 올리거나, BOM 버전 속성으로 오버라이드한다(검증된 조합이 깨지므로 근거를 남긴다). 현재 릴리스 라인에는 공개 수정 버전이 없어 3.5.x 라인으로 옮겨야 한다.

### org.springframework.data:spring-data-keyvalue:3.3.5 — MODERATE

- 권고 1건: GHSA-xg2j-3hj6-pc24(MODERATE)
- 버전 결정: Spring Boot BOM(dependency-management 플러그인)이 관리 버전 3.3.5으로 결정
- 유입: 직접 의존성 1개 경로
  - spring-boot-starter-data-redis:3.3.5 → spring-data-redis:3.3.5 → spring-data-keyvalue:3.3.5
- 수정 버전: 3.5.12 (릴리스 라인 변경 필요)
- 조치: **Spring Boot(BOM) 업그레이드** — Spring Boot BOM이 관리하는 버전이다. 3.5.12 이상을 관리하는 Spring Boot로 올리거나, BOM 버전 속성으로 오버라이드한다(검증된 조합이 깨지므로 근거를 남긴다). 현재 릴리스 라인에는 공개 수정 버전이 없어 3.5.x 라인으로 옮겨야 한다.

### org.springframework.retry:spring-retry:2.0.10 — MODERATE

- 권고 1건: GHSA-2827-2mxx-j8pv(MODERATE)
- 버전 결정: Spring Boot BOM(dependency-management 플러그인)이 관리 버전 2.0.10으로 결정 (전이 요청: 2.0.6)
- 유입: 직접 의존성 1개 경로
  - spring-boot-starter-batch:3.3.5 → spring-batch-core:5.1.2 → spring-batch-infrastructure:5.1.2 → spring-retry:2.0.10
- 수정 버전: 2.0.13
- 조치: **Spring Boot(BOM) 업그레이드** — Spring Boot BOM이 관리하는 버전이다. 2.0.13 이상을 관리하는 Spring Boot로 올리거나, BOM 버전 속성으로 오버라이드한다(검증된 조합이 깨지므로 근거를 남긴다).

### org.springframework.security:spring-security-core:6.3.4 — MODERATE

- 권고 2건: GHSA-q3v6-hm2v-pw99(MODERATE), GHSA-vxf7-qj7q-83fh(LOW)
- 버전 결정: Spring Boot BOM(dependency-management 플러그인)이 관리 버전 6.3.4으로 결정
- 유입: 직접 의존성 2개 경로
  - spring-boot-starter-oauth2-client:3.3.5 → spring-security-core:6.3.4
  - spring-boot-starter-security:3.3.5 → spring-security-config:6.3.4 → spring-security-core:6.3.4
- 수정 버전: 6.5.10 (릴리스 라인 변경 필요)
- 조치: **Spring Boot(BOM) 업그레이드** — Spring Boot BOM이 관리하는 버전이다. 6.5.10 이상을 관리하는 Spring Boot로 올리거나, BOM 버전 속성으로 오버라이드한다(검증된 조합이 깨지므로 근거를 남긴다). 현재 릴리스 라인에는 공개 수정 버전이 없어 6.5.x 라인으로 옮겨야 한다.

### org.springframework.security:spring-security-oauth2-jose:6.3.4 — MODERATE

- 권고 1건: GHSA-cvc6-q2cp-2xhw(MODERATE)
- 버전 결정: Spring Boot BOM(dependency-management 플러그인)이 관리 버전 6.3.4으로 결정
- 유입: 직접 의존성 1개 경로
  - spring-boot-starter-oauth2-client:3.3.5 → spring-security-oauth2-jose:6.3.4
- 수정 버전: 6.5.10 (릴리스 라인 변경 필요)
- 조치: **Spring Boot(BOM) 업그레이드** — Spring Boot BOM이 관리하는 버전이다. 6.5.10 이상을 관리하는 Spring Boot로 올리거나, BOM 버전 속성으로 오버라이드한다(검증된 조합이 깨지므로 근거를 남긴다). 현재 릴리스 라인에는 공개 수정 버전이 없어 6.5.x 라인으로 옮겨야 한다.

### org.springframework:spring-web:6.1.14 — MODERATE

- 권고 1건: GHSA-6r3c-xf4w-jxjm(MODERATE)
- 버전 결정: Spring Boot BOM(dependency-management 플러그인)이 관리 버전 6.1.14으로 결정
- 유입: 직접 의존성 5개 경로
  - spring-boot-starter-web:3.3.5 → spring-web:6.1.14
  - spring-boot-starter-webflux:3.3.5 → spring-web:6.1.14
  - spring-boot-starter-security:3.3.5 → spring-security-web:6.3.4 → spring-web:6.1.14
- 수정 버전: 6.1.21
- 조치: **Spring Boot(BOM) 업그레이드** — Spring Boot BOM이 관리하는 버전이다. 6.1.21 이상을 관리하는 Spring Boot로 올리거나, BOM 버전 속성으로 오버라이드한다(검증된 조합이 깨지므로 근거를 남긴다).

### io.netty:netty-handler-proxy:4.1.114.Final — LOW

- 권고 1건: GHSA-45q3-82m4-75jr(LOW)
- 버전 결정: Spring Boot BOM(dependency-management 플러그인)이 관리 버전 4.1.114.Final으로 결정
- 유입: 직접 의존성 1개 경로
  - spring-boot-starter-webflux:3.3.5 → spring-boot-starter-reactor-netty:3.3.5 → reactor-netty-http:1.1.23 → reactor-netty-core:1.1.23 → netty-handler-proxy:4.1.114.Final
- 수정 버전: 4.1.133.Final
- 조치: **Spring Boot(BOM) 업그레이드** — Spring Boot BOM이 관리하는 버전이다. 4.1.133.Final 이상을 관리하는 Spring Boot로 올리거나, BOM 버전 속성으로 오버라이드한다(검증된 조합이 깨지므로 근거를 남긴다).

### org.springframework:spring-context:6.1.14 — LOW

- 권고 1건: GHSA-4wp7-92pw-q264(LOW)
- 버전 결정: Spring Boot BOM(dependency-management 플러그인)이 관리 버전 6.1.14으로 결정 (전이 요청: 6.1.14, 5.2.12.RELEASE, 6.1.7)
- 유입: 직접 의존성 10개 경로
  - spring-boot-starter-batch:3.3.5 → spring-batch-core:5.1.2 → spring-context:6.1.14
  - spring-boot-starter-data-jpa:3.3.5 → spring-data-jpa:3.3.5 → spring-context:6.1.14
  - spring-boot-starter-oauth2-client:3.3.5 → spring-security-config:6.3.4 → spring-context:6.1.14
- 수정 버전: 6.1.20
- 조치: **Spring Boot(BOM) 업그레이드** — Spring Boot BOM이 관리하는 버전이다. 6.1.20 이상을 관리하는 Spring Boot로 올리거나, BOM 버전 속성으로 오버라이드한다(검증된 조합이 깨지므로 근거를 남긴다).

## 테스트 범위 (배포물 미포함, 보고만)

- org.assertj:assertj-core:3.25.3 — HIGH, 권고 1건, 구성: testRuntimeClasspath
- org.xmlunit:xmlunit-core:2.9.1 — LOW, 권고 1건, 구성: testRuntimeClasspath
