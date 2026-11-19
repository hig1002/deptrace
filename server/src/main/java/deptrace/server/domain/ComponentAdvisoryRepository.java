package deptrace.server.domain;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface ComponentAdvisoryRepository extends JpaRepository<ComponentAdvisory, ComponentAdvisory.Key> {

    List<ComponentAdvisory> findByKeyComponentIdIn(Collection<Long> componentIds);

    /** 현재 스냅샷 기준으로 이 프로젝트가 받아야 할 (구성요소, 권고) 쌍. */
    @Query("""
            select ca from Project p join p.currentSnapshot s join s.components c, ComponentAdvisory ca
            where p.id = :projectId and ca.key.componentId = c.id
            """)
    List<ComponentAdvisory> findForProject(@Param("projectId") Long projectId);
}
