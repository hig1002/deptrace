package deptrace.server.domain;

import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.Set;

import jakarta.persistence.CollectionTable;
import jakarta.persistence.Column;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;

import deptrace.osv.OsvVulnerability;
import deptrace.osv.Severity;

/** OSV 권고. CVE 같은 별칭으로도 찾을 수 있게 별칭 테이블을 둔다. */
@Entity
public class Advisory {

    @Id
    private String id;

    @Column(columnDefinition = "text")
    private String summary;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Severity severity;

    private String modified;

    @Column(nullable = false)
    private Instant updatedAt;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "advisory_alias", joinColumns = @JoinColumn(name = "advisory_id"))
    @Column(name = "alias")
    private Set<String> aliases = new LinkedHashSet<>();

    protected Advisory() {
    }

    public Advisory(String id) {
        this.id = id;
    }

    /** OSV 원문이 바뀌었으면(심각도 재평가, 별칭 추가) 반영한다. */
    public void update(OsvVulnerability v, Instant now) {
        this.summary = v.summary();
        this.severity = v.severity();
        this.modified = v.modified();
        this.aliases.clear();
        this.aliases.addAll(v.aliases());
        this.updatedAt = now;
    }

    public String getId() {
        return id;
    }

    public String getSummary() {
        return summary;
    }

    public Severity getSeverity() {
        return severity;
    }

    public Set<String> getAliases() {
        return aliases;
    }
}
