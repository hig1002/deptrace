# 사례: Maven 지원 검증 (spring-batch-extensions)

| 항목 | 내용 |
|---|---|
| 대상 | [spring-projects/spring-batch-extensions](https://github.com/spring-projects/spring-batch-extensions)의 개인 포크. 모듈 6개(bigquery, elasticsearch, excel, neo4j, notion, s3), 각각 독립된 Maven 프로젝트 |
| 도구 | Maven 3.9.11, maven-dependency-plugin 3.9.0 |
| 점검일 | 2026-11-18 |
| 목적 | Maven 추출기([ADR 0007](../adr/0007-maven-extraction.md))가 Maven의 해석 결과를 정확히 옮기는지 확인 |

## 1. 추출 정확도

모듈마다 `deptrace maven-export`의 결과와 Maven의 `dependency:list`(정답)를 비교했습니다.

| 모듈 | 실행 범위 (정답 / 일치) | 전체 (정답 / 일치) |
|---|---|---|
| bigquery | 180 / 180 | 201 / 201 |
| elasticsearch | 41 / 41 | 44 / 44 |
| excel | 30 / 30 | 45 / 45 |
| neo4j | 38 / 38 | 50 / 50 |
| notion | 12 / 12 | 120 / 120 |
| s3 | 51 / 51 | 65 / 65 |
| **합계** | **357 / 357** | **525 / 525** |

누락과 초과는 모두 0이었습니다. 해석 실패한 엣지도 없었습니다.

## 2. Maven에서만 생기는 버전 하향

실행 범위에서, 어떤 라이브러리가 요청한 버전보다 낮은 버전이 선택된 경우가 4건 있었습니다. Gradle 기본 충돌 해결(항상 최고 버전)에서는 생기지 않는 유형이 포함돼 있습니다.

| 모듈 | 구성요소 | 요청 → 선택 | 원인 |
|---|---|---|---|
| neo4j | io.netty:netty-handler | 4.2.2.Final → **4.1.127.Final** | dependencyManagement가 Neo4j 드라이버의 요청을 **이전 마이너 라인**으로 덮어씀 |
| bigquery | org.apache.commons:commons-text | 1.11.0 → 1.10.0 | nearest-wins: 루트에 더 가까운 경로의 1.10.0이 선택됨 |
| neo4j | org.apiguardian:apiguardian-api | 1.1.2 → 1.1.1 | nearest-wins |
| excel | commons-codec:commons-codec | 1.20.0 → 1.19.0 | dependencyManagement |

neo4j의 netty-handler는 마이너 라인까지 바뀌는 하향입니다. 드라이버(neo4j-bolt-connection-netty)가 4.2 라인을 기준으로 만들어졌다면 실행 중 호환성 문제가 생길 수 있어, 확인이 필요한 항목입니다. DepTrace는 이것을 `BOM_MANAGED` + "하향"으로 분류하고, 조치를 `<properties>`·`<dependencyManagement>` 기준으로 안내합니다.

`deptrace explain` 출력 (테스트 범위의 nearest-wins 예):

```
org.eclipse.jetty.ee10:jetty-ee10-servlet:12.1.6  [maven:test]
  선택 사유(Maven): REQUESTED, CONFLICT_RESOLUTION
  요청 버전: 12.0.30, 12.1.6  직접 선언: -  BOM 관리: -
  분류: CONFLICT_RESOLUTION — Maven nearest-wins: 루트에 더 가까운 경로의 버전이 선택됨 (nearest-wins: 12.0.30 요청보다 루트에 가까운 12.1.6 선택)
```

## 3. 이후 단계가 그대로 동작하는지

Maven 그래프에 `analyze`, `nvd-gaps`, `licenses`, `sbom`을 그대로 실행했습니다. 6개 모듈 모두 오류 없이 결과를 냈습니다.

| 모듈 | 취약 구성요소 / 고유 취약점 (OSV) | OSV 미반영 (NVD 보완, 미검증) | 라이선스 검토 필요 | SBOM 구성요소 |
|---|---|---|---|---|
| bigquery | 25 / 58 | 29 | 9 | 180 |
| elasticsearch | 13 / 133 | 23 | 1 | 41 |
| excel | 5 / 8 | 28 | 0 | 30 |
| neo4j | 7 / 18 | 33 | 1 | 38 |
| notion | 5 / 23 | 30 | 0 | 12 |
| s3 | 4 / 7 | 28 | 0 | 51 |

- **"OSV 미반영" 수치는 검증하지 않았습니다.** 경매톡처럼 다른 도구(Dependency-Check)와 교차 검증한 결과가 아닙니다. 모든 모듈이 Spring Framework 7.0.5를 쓰고 있어, 경매톡에서 본 Spring 미검토 권고들이 공통으로 잡힌 것으로 보입니다. 확인은 후속 과제입니다.
- 이 표는 Maven 그래프가 이후 단계와 호환되는지 확인하려고 만든 것입니다. 각 모듈의 취약점 판단(실제 영향, 조치)은 하지 않았습니다.

## 후속 과제

- 이 프로젝트에서도 Dependency-Check와 교차 검증해 NVD 보완 점검의 정확도 재측정 (경매톡 한 곳의 측정을 일반화하기 위해)
- elasticsearch 모듈의 취약점(고유 133건) 내용 확인. 업스트림에 의존성 상향을 제안할 수 있는지 검토
- neo4j의 netty-handler 하향이 드라이버 동작에 영향을 주는지 확인
