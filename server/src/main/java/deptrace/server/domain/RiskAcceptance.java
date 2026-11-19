package deptrace.server.domain;

import java.time.Instant;
import java.time.LocalDate;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;

/**
 * 예외(위험 수용). "지금 영향이 없다"는 판단이지 "앞으로도 없다"는 판단이 아니므로,
 * 사유와 만료일이 반드시 있고 만료되면 발견이 다시 열린다 (ADR 0003).
 */
@Entity
public class RiskAcceptance {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "project_id")
    private Project project;

    /** GHSA ID 또는 CVE 같은 별칭. 사람은 보통 CVE 번호로 말하므로 둘 다 받는다. */
    @Column(nullable = false)
    private String advisoryRef;

    /** group:artifact. null이면 이 권고가 걸린 이 프로젝트의 모든 구성요소에 적용한다. */
    private String module;

    @Column(nullable = false, columnDefinition = "text")
    private String reason;

    @Column(nullable = false)
    private LocalDate expiresOn;

    private String requestedBy;

    @Column(nullable = false)
    private Instant createdAt;

    private Instant revokedAt;

    protected RiskAcceptance() {
    }

    public RiskAcceptance(Project project, String advisoryRef, String module, String reason, LocalDate expiresOn,
                          String requestedBy, Instant now) {
        this.project = project;
        this.advisoryRef = advisoryRef;
        this.module = module;
        this.reason = reason;
        this.expiresOn = expiresOn;
        this.requestedBy = requestedBy;
        this.createdAt = now;
    }

    /** 만료일 당일까지 유효하다 (CLI PolicyGate와 같음). */
    public boolean isActive(LocalDate today) {
        return revokedAt == null && !expiresOn.isBefore(today);
    }

    /** 이 예외가 (구성요소, 권고)에 해당하는지. CLI PolicyGate.matches와 같은 규칙. */
    public boolean covers(Component component, Advisory advisory) {
        boolean advisoryMatches = advisoryRef.equals(advisory.getId()) || advisory.getAliases().contains(advisoryRef);
        boolean moduleMatches = module == null || module.equals(component.module());
        return advisoryMatches && moduleMatches;
    }

    public void revoke(Instant now) {
        this.revokedAt = now;
    }

    public Long getId() {
        return id;
    }

    public Project getProject() {
        return project;
    }

    public String getAdvisoryRef() {
        return advisoryRef;
    }

    public String getModule() {
        return module;
    }

    public String getReason() {
        return reason;
    }

    public LocalDate getExpiresOn() {
        return expiresOn;
    }

    public String getRequestedBy() {
        return requestedBy;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getRevokedAt() {
        return revokedAt;
    }
}
