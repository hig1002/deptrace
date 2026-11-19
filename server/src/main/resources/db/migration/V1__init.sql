-- 프로젝트: SBOM을 올리는 단위 (서비스 하나)
create table project (
    id                  bigserial primary key,
    project_key         varchar(100) not null unique,
    created_at          timestamptz  not null,
    current_snapshot_id bigint
);

-- 구성요소: 모든 프로젝트가 공유한다. 같은 버전은 한 번만 OSV에 조회하기 위해서다
create table component (
    id              bigserial primary key,
    group_id        varchar(255) not null,
    artifact_id     varchar(255) not null,
    version         varchar(255) not null,
    purl            varchar(800) not null unique,
    last_scanned_at timestamptz
);
create index ix_component_module on component (group_id, artifact_id);

-- 스냅샷: SBOM 업로드 한 번. 프로젝트의 현재 스냅샷만 판정 대상이다
create table snapshot (
    id              bigserial primary key,
    project_id      bigint      not null references project (id),
    created_at      timestamptz not null,
    component_count int         not null,
    source          varchar(255)
);
alter table project add constraint fk_project_current_snapshot foreign key (current_snapshot_id) references snapshot (id);

create table snapshot_component (
    snapshot_id  bigint not null references snapshot (id),
    component_id bigint not null references component (id),
    primary key (snapshot_id, component_id)
);
create index ix_snapshot_component_component on snapshot_component (component_id);

-- 권고: OSV 권고 원문의 요약
create table advisory (
    id         varchar(100) primary key,
    summary    text,
    severity   varchar(20) not null,
    modified   varchar(50),
    updated_at timestamptz not null
);

create table advisory_alias (
    advisory_id varchar(100) not null references advisory (id),
    alias       varchar(100) not null,
    primary key (advisory_id, alias)
);
create index ix_advisory_alias_alias on advisory_alias (alias);

-- 구성요소 버전 ↔ 권고 대응. 프로젝트와 무관한 사실이라 전역으로 한 번만 저장한다
create table component_advisory (
    component_id  bigint       not null references component (id),
    advisory_id   varchar(100) not null references advisory (id),
    first_seen_at timestamptz  not null,
    primary key (component_id, advisory_id)
);
create index ix_component_advisory_advisory on component_advisory (advisory_id);

-- 발견: 프로젝트별 상태. (프로젝트, 구성요소, 권고)당 하나라서 재실행해도 중복되지 않는다
create table finding (
    id            bigserial primary key,
    project_id    bigint       not null references project (id),
    component_id  bigint       not null references component (id),
    advisory_id   varchar(100) not null references advisory (id),
    status        varchar(20)  not null,
    detected_by   varchar(20)  not null,
    first_seen_at timestamptz  not null,
    resolved_at   timestamptz,
    reopened_at   timestamptz,
    constraint uq_finding unique (project_id, component_id, advisory_id)
);
create index ix_finding_project_status on finding (project_id, status);
