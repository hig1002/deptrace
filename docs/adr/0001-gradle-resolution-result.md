# 0001. Gradle 해석 결과는 ResolutionResult API로 추출한다

- 상태: 채택 (2026-10-19)

## 맥락

"왜 이 버전인가"를 답하려면 요청 버전, 선택 버전, 선택 사유가 필요하다. 후보는 셋이었다.

1. `gradle dependencies` 텍스트 출력 파싱
2. 의존성 해석 규칙 직접 구현 (POM/BOM 읽기, 충돌 해결 재현)
3. Gradle의 `ResolutionResult` API로 해석 결과를 구조화해 추출

## 결정

3을 택한다. init script로 주입해 분석 대상의 빌드 파일은 수정하지 않는다.

## 근거

- **1을 택하지 않은 이유**
  - 텍스트 형식은 공개 계약이 아니다. 출력 형식에 기댄 파서는 Gradle 버전이 바뀌면 깨질 수 있다.
  - `(*)`로 생략되는 반복 노드가 있다.
  - `->` 표기로는 충돌 해결로 바뀐 것인지 BOM 규칙으로 바뀐 것인지 구분할 수 없다.
- **2를 택하지 않은 이유**
  - Gradle 해석에는 BOM, platform, 제약, rich version, 변형(variant) 선택, dependency-management 플러그인 규칙이 섞여 있다.
  - 재구현하면 정답과의 오차만 생긴다. 정답은 Gradle이고, 이 도구의 가치는 정답을 **설명 가능한 형태로 꺼내는 데** 있다.
- **3이 주는 것**
  - `ComponentSelectionReason`(REQUESTED, CONFLICT_RESOLUTION, SELECTED_BY_RULE, CONSTRAINT, FORCED 등)
  - 엣지별 `requested` 셀렉터, 제약 엣지 여부(`isConstraint`)
  - 실제 경매톡에서 dependency-management 플러그인이 직접 선언 버전(9.37)으로 더 높은 전이 요청(9.37.3)을 덮어쓴 사실은 이 정보로만 드러났다.

## 결과와 한계

- 빌드를 실행할 수 있어야 한다. 빌드할 수 없는 입력은 별도의 정적 해석기가 필요하며, 이 추출 결과를 그 정답 데이터로 쓸 수 있다.
- 실행 시점에 프로젝트 모델을 읽으므로 구성 캐시와 호환되지 않는다(`--no-configuration-cache`).
