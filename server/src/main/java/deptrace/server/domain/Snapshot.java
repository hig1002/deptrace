package deptrace.server.domain;

import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.Set;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.ManyToOne;

/** SBOM 업로드 한 번. 배포물에 무엇이 들어 있었는지의 기록이다. */
@Entity
public class Snapshot {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "project_id")
    private Project project;

    @Column(nullable = false)
    private Instant createdAt;

    @Column(nullable = false)
    private int componentCount;

    private String source;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(name = "snapshot_component",
            joinColumns = @JoinColumn(name = "snapshot_id"),
            inverseJoinColumns = @JoinColumn(name = "component_id"))
    private Set<Component> components = new LinkedHashSet<>();

    protected Snapshot() {
    }

    public Snapshot(Project project, Set<Component> components, String source, Instant now) {
        this.project = project;
        this.components = components;
        this.componentCount = components.size();
        this.source = source;
        this.createdAt = now;
    }

    public Long getId() {
        return id;
    }

    public Set<Component> getComponents() {
        return components;
    }
}
