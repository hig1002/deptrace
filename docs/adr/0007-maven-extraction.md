# 0007. Maven은 Maven이 해석한 결과(verbose 트리)를 옮기고, 해석 규칙을 다시 구현하지 않는다

- 상태: 채택 (2026-11-18)

## 맥락

Maven과 Gradle은 같은 의존성 선언에서 다른 버전을 고를 수 있다.

| | Gradle | Maven |
|---|---|---|
| 충돌 해결 | 요청 중 가장 높은 버전 | 루트에 가장 가까운 선언 (nearest-wins), 깊이가 같으면 먼저 선언된 것 |
| 하향 | dependency-management 플러그인 규칙이 있을 때만 | nearest-wins만으로도 생김 |
| 버전 관리 | platform/BOM, constraints | dependencyManagement (부모 POM 상속, BOM import) |

그래서 Gradle 추출기를 그대로 쓸 수 없고, Maven용 추출기가 필요했다.

## 결정

1. **Maven이 해석한 결과를 옮긴다.** `maven-dependency-plugin:3.9.0:tree -Dverbose` 출력을 그래프로 바꾼다. Gradle에서 `ResolutionResult`를 쓴 것(ADR 0001)과 같은 이유다. 해석 규칙을 다시 구현하면 오차만 생긴다.
2. **verbose 주석을 선택 사유로 옮긴다.**
   - `omitted for conflict with V` → 이긴 버전 V 노드에 `CONFLICT_RESOLUTION`(nearest-wins). 생략된 줄의 버전은 그 경로의 요청 버전으로 엣지에 남긴다.
   - `version managed from X` → `SELECTED_BY_RULE`(dependencyManagement). X는 엣지의 요청 버전이 된다.
   - `omitted for duplicate` → 노드는 이미 있으므로 엣지만 추가한다.
3. **직접 선언 여부는 pom.xml에서 읽는다.** 트리는 직접 의존성의 버전이 pom.xml에 적힌 것인지 dependencyManagement에서 온 것인지 구분하지 않는다. Maven에서는 직접 적은 버전이 관리 버전보다 우선하므로, 이 구분이 수정 지점을 바꾼다.
4. **구성은 두 개.** `maven:runtime`(compile·runtime, 실행 jar에 들어가는 범위)을 기준 구성으로, `maven:test`(provided·test 포함)를 분리한다.
5. **설명과 조치를 Maven 기준으로 쓴다.** "가장 높은 버전 선택" 대신 nearest-wins로 설명한다. 조치도 Gradle `constraints {}`가 아니라 `<dependencyManagement>`·부모 POM 속성으로 안내한다.
6. **플러그인 버전을 고정한다.** verbose 출력 형식은 플러그인 버전마다 다를 수 있다.

## 근거: 측정

spring-batch-extensions 6개 모듈에서 같은 Maven으로 `dependency:list`(정답)를 만들어 비교했다.

| 구성 | 정답 구성요소 | 일치 | 누락 | 초과 |
|---|---|---|---|---|
| 실행 범위 (6개 모듈 합) | 357 | 357 | 0 | 0 |
| 전체 (6개 모듈 합) | 525 | 525 | 0 | 0 |

## 한계

- Maven을 실행할 수 있어야 한다. pom.xml만으로 해석하는 정적 해석기는 다음 과제이고, 이 추출 결과가 그 정답 데이터가 된다.
- 모듈 하나씩 추출한다. reactor 빌드는 모듈마다 실행한다.
- 노드를 group:artifact:version으로 식별한다. classifier만 다른 jar는 하나로 합쳐진다.
- `dependency:list`와 구성요소 집합이 일치하는 것만 측정했다. 선택 사유(nearest-wins·관리)의 정확성은 verbose 주석을 그대로 옮긴 것이라 별도로 측정하지 않았다.
