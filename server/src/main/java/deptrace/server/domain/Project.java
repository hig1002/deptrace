package deptrace.server.domain;

import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.OneToOne;

@Entity
public class Project {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "project_key", nullable = false, unique = true)
    private String key;

    @Column(nullable = false)
    private Instant createdAt;

    /** 판정 대상이 되는 최신 스냅샷. 이전 스냅샷은 이력으로만 남는다. */
    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "current_snapshot_id")
    private Snapshot currentSnapshot;

    protected Project() {
    }

    public Project(String key, Instant now) {
        this.key = key;
        this.createdAt = now;
    }

    public void replaceSnapshot(Snapshot snapshot) {
        this.currentSnapshot = snapshot;
    }

    public Long getId() {
        return id;
    }

    public String getKey() {
        return key;
    }

    public Snapshot getCurrentSnapshot() {
        return currentSnapshot;
    }
}
