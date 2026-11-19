package deptrace.server.domain;

import java.io.Serializable;
import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import jakarta.persistence.EmbeddedId;
import jakarta.persistence.Entity;

/** "이 구성요소 버전에 이 권고가 걸린다"는 사실. 프로젝트와 무관해서 전역으로 한 번만 저장한다. */
@Entity
public class ComponentAdvisory {

    @Embeddable
    public record Key(@Column(name = "component_id") Long componentId,
                      @Column(name = "advisory_id") String advisoryId) implements Serializable {
    }

    @EmbeddedId
    private Key key;

    @Column(nullable = false)
    private Instant firstSeenAt;

    protected ComponentAdvisory() {
    }

    public ComponentAdvisory(Long componentId, String advisoryId, Instant now) {
        this.key = new Key(componentId, advisoryId);
        this.firstSeenAt = now;
    }

    public Key getKey() {
        return key;
    }
}
