-- 예외(위험 수용). CLI의 deptrace-exceptions.yml과 같은 규칙: 사유와 만료일이 있어야 인정한다 (ADR 0003)
create table risk_acceptance (
    id           bigserial primary key,
    project_id   bigint       not null references project (id),
    advisory_ref varchar(100) not null,   -- GHSA ID 또는 CVE 같은 별칭
    module       varchar(500),            -- group:artifact. 비우면 이 권고가 걸린 모든 구성요소
    reason       text         not null,
    expires_on   date         not null,
    requested_by varchar(200),
    created_at   timestamptz  not null,
    revoked_at   timestamptz
);
create index ix_risk_acceptance_project on risk_acceptance (project_id);

alter table finding add column risk_acceptance_id bigint references risk_acceptance (id);
alter table finding add column accepted_at timestamptz;
