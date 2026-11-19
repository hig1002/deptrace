package deptrace.server.domain;

import java.time.Duration;
import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;

import deptrace.model.Coordinate;

/** 구성요소 버전 하나. 모든 프로젝트가 공유해서, 같은 버전은 OSV에 한 번만 묻는다. */
@Entity
public class Component {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String groupId;

    @Column(nullable = false)
    private String artifactId;

    @Column(nullable = false)
    private String version;

    @Column(nullable = false, unique = true)
    private String purl;

    private Instant lastScannedAt;

    protected Component() {
    }

    public Component(Coordinate c) {
        this.groupId = c.group();
        this.artifactId = c.artifact();
        this.version = c.version();
        this.purl = c.purl();
    }

    public Coordinate coordinate() {
        return new Coordinate(groupId, artifactId, version);
    }

    public boolean needsScan(Instant now, Duration freshFor) {
        return lastScannedAt == null || lastScannedAt.isBefore(now.minus(freshFor));
    }

    public void markScanned(Instant now) {
        this.lastScannedAt = now;
    }

    public Long getId() {
        return id;
    }

    public String getPurl() {
        return purl;
    }

    public String module() {
        return groupId + ":" + artifactId;
    }

    public String getVersion() {
        return version;
    }
}
