package deptrace.server.domain;

import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;

/**
 * 프로젝트별 발견. (프로젝트, 구성요소, 권고)당 하나만 있고 상태만 바뀐다.
 * 그래서 같은 SBOM을 다시 올리거나 재검사를 두 번 돌려도 중복이 생기지 않는다.
 */
@Entity
public class Finding {

    /** ACCEPTED: 유효한 예외(사유·만료일)가 있어 위험을 수용한 상태. 만료·철회되면 OPEN으로 돌아간다. */
    public enum Status { OPEN, ACCEPTED, RESOLVED }

    /** UPLOAD: SBOM을 올릴 때 발견, RESCAN: 코드 변경 없이 새 권고가 공개돼 재검사에서 발견 */
    public enum DetectedBy { UPLOAD, RESCAN }

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "project_id")
    private Project project;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "component_id")
    private Component component;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "advisory_id")
    private Advisory advisory;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Status status;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private DetectedBy detectedBy;

    @Column(nullable = false)
    private Instant firstSeenAt;

    private Instant resolvedAt;

    private Instant reopenedAt;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "risk_acceptance_id")
    private RiskAcceptance acceptance;

    private Instant acceptedAt;

    protected Finding() {
    }

    /** 예외로 위험을 수용한다. 해결된 것이 다시 나타났는데 예외가 있으면 바로 수용 상태가 된다. */
    public void accept(RiskAcceptance acceptance, Instant now) {
        if (this.status != Status.ACCEPTED || this.acceptance == null || !this.acceptance.getId().equals(acceptance.getId())) {
            this.acceptedAt = now;
        }
        this.status = Status.ACCEPTED;
        this.acceptance = acceptance;
        this.resolvedAt = null;
    }

    /** 예외가 만료·철회돼 다시 조치 대상이 됨. */
    public void endAcceptance(Instant now) {
        this.status = Status.OPEN;
        this.acceptance = null;
        this.acceptedAt = null;
        this.reopenedAt = now;
    }

    public Finding(Project project, Component component, Advisory advisory, DetectedBy detectedBy, Instant now) {
        this.project = project;
        this.component = component;
        this.advisory = advisory;
        this.status = Status.OPEN;
        this.detectedBy = detectedBy;
        this.firstSeenAt = now;
    }

    public void resolve(Instant now) {
        this.status = Status.RESOLVED;
        this.resolvedAt = now;
        this.acceptance = null;
        this.acceptedAt = null;
    }

    public RiskAcceptance getAcceptance() {
        return acceptance;
    }

    public Instant getAcceptedAt() {
        return acceptedAt;
    }

    /** 해결됐던 것이 다시 나타남 (예: 버전을 되돌림). */
    public void reopen(Instant now) {
        this.status = Status.OPEN;
        this.reopenedAt = now;
        this.resolvedAt = null;
    }

    public Long getId() {
        return id;
    }

    public Project getProject() {
        return project;
    }

    public Component getComponent() {
        return component;
    }

    public Advisory getAdvisory() {
        return advisory;
    }

    public Status getStatus() {
        return status;
    }

    public DetectedBy getDetectedBy() {
        return detectedBy;
    }

    public Instant getFirstSeenAt() {
        return firstSeenAt;
    }

    public Instant getResolvedAt() {
        return resolvedAt;
    }

    public Instant getReopenedAt() {
        return reopenedAt;
    }
}
