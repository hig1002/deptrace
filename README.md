# DepTrace

Gradle 의존성 해석 결과에 OSV 취약점 정보를 결합해, 취약한 구성요소가 **어떤 경로로 들어왔는지, 왜 그 버전이 선택됐는지, 어디를 고쳐야 하는지**를 알려주는 Java CLI입니다. CI에서 정책 게이트로도 동작합니다.

취약점 스캐너는 "무엇이 취약한가"를 알려줍니다. DepTrace는 그다음 질문에 답하려고 만들었습니다.

| 질문 | DepTrace가 보는 것 |
|---|---|
| 이 구성요소는 실제로 배포되는가? | 구성(configuration)별 해석 결과. bootJar가 쓰는 `productionRuntimeClasspath` 기준으로 판정하고 테스트 범위는 분리 |
| 왜 이 버전인가? | Gradle이 기록한 요청 버전, 선택 버전, 선택 사유(충돌 해결·BOM 규칙·제약·강제) |
| 누가 끌고 왔는가? | 직접 의존성(1차 유입자)별 최단 유입 경로 |
| 어디를 고쳐야 하는가? | 버전을 결정한 주체에 따라 직접 선언 제거·상향 / Spring Boot(BOM) 업그레이드 / constraints / 수정 불가로 분류 |
| 고친 뒤 정말 바뀌었는가? | 수정 전후 구성요소·취약점 비교(상향·하향·추가·제거, 해결·신규·잔존) |

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

| 명령 | 설명 |
|---|---|
| `deptrace explain --graphs build/deptrace com.nimbusds:nimbus-jose-jwt` | 구성요소 하나의 버전 결정 원인과 유입 경로 (오프라인) |
| `deptrace analyze --graphs build/deptrace --out build/deptrace-report --fail-on HIGH --exceptions deptrace-exceptions.yml` | 전체 분석, 리포트 생성, 정책 게이트 (위반 시 종료 코드 1) |
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

- 단위 테스트 32개 (`./gradlew test`)
  - 버전 결정 분류: 하향, BOM 덮어쓰기, 범위 이탈, 충돌 해결
  - 유입 경로: 최단 경로, 제약 엣지 제외, 순환
  - 영향 범위 해석: 라인 변경, 재발 범위, 정렬, 좌표 이동
  - 실배포 버전 선택(변형 꼬리표 유지 포함), 정책 게이트(예외 만료·패키지 불일치·설정 오류), 전후 비교
- 테스트 데이터는 경매톡에서 실제로 관찰한 사례(nimbus-jose-jwt, querydsl, json-smart, httpclient5, protobuf, ion-java, Tomcat 10.1.58, guava 33.7.2-jre)를 그대로 옮겼습니다.
- OSV-Scanner와의 차분 비교: 경매톡 배포 클래스패스 기준 (구성요소, 권고 ID) 163쌍이 모두 일치했습니다.

## 한계와 다음 단계

- **도달 가능성:** 함수 단위 도달 가능성은 분석하지 않습니다. 예외 판단의 근거는 기능 단위 코드 검색이며, 사람이 판단합니다.
- **빌드 시스템:** Gradle만 지원합니다.
  - Maven은 가까운 선언이 이기는(nearest-wins) 다른 해석 규칙을 쓰므로 별도 추출기가 필요합니다.
  - 빌드를 실행할 수 없는 입력(매니페스트만 있는 경우)도 지원하지 않습니다. 다음 단계는 정적 해석기를 만들고, 이 도구의 추출 결과를 정답 데이터로 삼아 정확도를 측정하는 것입니다.
- **바이너리 분석:** bootJar 안의 JAR와 재패키징(shading)된 라이브러리 식별은 하지 않습니다. 해석 그래프에 나타나지 않는 구성요소는 보지 못합니다.
- **데이터 범위:** 취약점 데이터는 OSV에 의존하고, 라이선스는 아직 다루지 않습니다.
