# DepTrace 서버

CLI는 빌드 한 번을 그 시점에 점검합니다. 실제로 필요한 질문은 그다음입니다.

- 오늘 새 CVE가 공개됐다. **코드를 바꾸지 않았는데**, 우리 서비스 중 어디가 영향을 받는가?
- Log4Shell 같은 대형 취약점이 터졌다. **어느 프로젝트가 log4j-core를 어떤 버전으로** 쓰고 있는가?
- 지난달에 있던 취약점은 **해결됐는가, 다시 생겼는가?**

서버는 CI가 올린 SBOM을 저장하고, 매일 OSV와 다시 대조해 이 질문에 답합니다. 설계 근거는 [ADR 0008](adr/0008-server-design.md)에 있습니다.

## 흐름

```
CI ── deptrace sbom ──▶ POST /api/projects/{key}/sboms
                              │ 1. 스냅샷 저장 (짧은 트랜잭션)
                              │ 2. 24시간 안에 조회하지 않은 구성요소만 OSV 조회 (트랜잭션 밖)
                              │ 3. 발견 상태 맞추기 → 새 발견 알림
                              ▼
                  PostgreSQL: project · snapshot · component · advisory
                              component_advisory (버전↔권고, 전역)
                              finding (프로젝트별 상태: OPEN / RESOLVED)
                              ▲
매일 00:00 UTC ── Spring Batch rescanJob
                  scan: 사용 중인 구성요소를 중복 없이 청크로 OSV 재조회
                  reconcile: 프로젝트마다 상태 맞추기 → 새 발견 알림 (웹훅)
```

## API

| 메서드·경로 | 설명 |
|---|---|
| `POST /api/projects/{key}/sboms` | CycloneDX JSON 업로드. 결과: 구성요소 수, 조회한 수, 새로 열림·다시 열림·해결 수 |
| `GET /api/projects` | 프로젝트별 열린 발견 수 (심각도별) |
| `GET /api/projects/{key}/findings?status=OPEN` | 발견 목록 (권고 ID, 별칭, 심각도, 발견 경로 UPLOAD/RESCAN) |
| `GET /api/advisories/{GHSA 또는 CVE}/impact` | 이 권고에 영향받는 프로젝트와 구성요소. CVE 번호로도 찾음 |
| `GET /api/components/usage?module=group:artifact` | 이 라이브러리를 쓰는 프로젝트와 버전 (권고와 무관) |
| `POST /api/rescan` | 재검사 즉시 실행 |
| `POST /api/projects/{key}/exceptions` | 예외 등록: `{advisory, module?, reason, expiresOn, requestedBy?}`. 등록 즉시 해당 발견이 ACCEPTED |
| `GET /api/projects/{key}/exceptions` | 예외 목록 (ACTIVE / EXPIRED / REVOKED, 덮고 있는 발견 수) |
| `DELETE /api/projects/{key}/exceptions/{id}` | 철회. 기록은 남고 덮던 발견은 바로 OPEN |
| `GET /api/exceptions/expiring` | 14일 안에 만료되는 예외 (모든 프로젝트) |

쓰기 요청(GET·HEAD 외 모든 메서드)은 `Authorization: Bearer {DEPTRACE_API_TOKEN}`이 필요합니다.

## 예외(위험 수용)

CLI의 `deptrace-exceptions.yml`과 같은 규칙을 생명주기로 옮겼습니다([ADR 0009](adr/0009-server-risk-acceptance.md)).

```
OPEN ──(예외 등록)──▶ ACCEPTED ──(만료일 다음 날 재검사 / 철회)──▶ OPEN + "예외 종료" 알림
  │                                                              
  └──(버전 상향·제거, 권고 철회)──▶ RESOLVED ──(다시 나타남)──▶ OPEN (예외가 있으면 ACCEPTED)
```

- 권고는 GHSA ID나 CVE 번호 어느 쪽으로도 지정합니다. 모듈은 선택입니다.
- 사유는 10자 이상(확인 방법 포함), 만료일은 최대 180일입니다. 길게 잡으면 다시 볼 시점이 사라지기 때문입니다.
- 예외가 미리 있으면 새로 나타난 발견은 처음부터 ACCEPTED이고 알리지 않습니다.

## 실행

```bash
docker compose -f server/docker-compose.yml up -d
./gradlew :server:bootRun
```

| 환경 변수 | 기본값 | 설명 |
|---|---|---|
| `DEPTRACE_DB_URL` | `jdbc:postgresql://localhost:5432/deptrace` | |
| `DEPTRACE_API_TOKEN` | (없음 = 검사 안 함) | 쓰기 API 토큰 |
| `DEPTRACE_RESCAN_CRON` | `0 0 0 * * *` (UTC) | 재검사 시각 |
| `DEPTRACE_WEBHOOK_URL` | (없음) | 새 발견 알림 웹훅 (Slack incoming webhook 형식 `text` 포함) |

CI에서 올리는 예:

```bash
deptrace sbom --graphs build/deptrace --out bom.cdx.json
curl -X POST -H "Authorization: Bearer $DEPTRACE_API_TOKEN" -H "Content-Type: application/json" \
  --data-binary @bom.cdx.json "$DEPTRACE_SERVER/api/projects/my-service/sboms"
```

## 검증

**통합 테스트** (Testcontainers PostgreSQL 17, OSV만 고정 데이터, 시각을 움직일 수 있는 시계): 14개

- 업로드하면 발견이 열리고, 같은 SBOM을 다시 올려도 중복되지 않음
- 프로젝트가 달라도 같은 버전은 OSV에 한 번만 조회
- 코드 변경 없이 새 권고가 공개되면 재검사에서 잡고(`RESCAN`), 다시 돌려도 중복 없음
- 버전을 올리면 해결되고, CVE 번호로 영향받는 프로젝트를 찾음
- 권고가 철회되면 재검사에서 해결로 바뀜
- 쓰기 요청은 토큰 필요, 읽기는 불필요
- CycloneDX가 아니면 400
- 예외 7개: 등록(CVE 별칭) → 수용, 만료일 당일 유지·다음 날 다시 열림과 알림, 철회, 미리 등록한 예외, 다른 모듈 지정, 정책 위반 400, 곧 만료 목록

**실제 OSV로 실행** (2026-11-19, 로컬 PostgreSQL)

| 단계 | 결과 |
|---|---|
| 경매톡 SBOM 업로드 (292개) | 발견 9건 (구성요소 6개, 고유 권고 8건). **CLI `analyze`와 일치** |
| spring-batch-notion 업로드 (12개) | 11개만 조회 (1개는 경매톡에서 이미 조회), 발견 23건. CLI와 일치 |
| spring-batch-s3 업로드 (51개) | 39개만 조회, 발견 7건. CLI와 일치 |
| 경매톡 같은 SBOM 재업로드 | 조회 0개, 새 발견 0건, 0.04초 (첫 업로드 1.95초) |
| 재검사 2회 | 세 프로젝트의 구성요소 355개 중 중복을 뺀 342개 조회, 각 약 1.1초, 새 발견 0건 |
| `CVE-2026-47890` 영향 조회 | 경매톡의 spring-webmvc·spring-webflux 6.2.19 |
| 토큰 없는 POST | 401 |

## 한계

- NVD 보완 점검과 라이선스는 아직 서버에 없습니다. CLI에서만 됩니다.
- 예외에 승인 절차(요청자·승인자 분리)가 없고, CLI의 `deptrace-exceptions.yml`을 가져오는 기능도 없습니다. 두 곳에서 관리하면 어긋날 수 있습니다.
- 인증은 단일 토큰입니다. 프로젝트별 권한은 없습니다.
- 재검사의 OSV 상세 조회는 CLI와 같은 파일 캐시를 씁니다. 서버를 여러 대 띄우면 캐시와 스케줄 실행이 중복됩니다(분산 락 미적용).
- 측정은 프로젝트 3개, 구성요소 342개 규모입니다. 대규모 성능은 측정하지 않았습니다.
