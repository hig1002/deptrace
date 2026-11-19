package deptrace.server.domain;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface FindingRepository extends JpaRepository<Finding, Long> {

    List<Finding> findByProject(Project project);

    /** 이 예외가 지금 덮고 있는 발견 수. */
    long countByAcceptance(RiskAcceptance acceptance);

    @Query("""
            select f from Finding f join fetch f.component join fetch f.advisory
            where f.project = :project and (:status is null or f.status = :status)
            order by f.firstSeenAt desc
            """)
    List<Finding> findForProject(@Param("project") Project project, @Param("status") Finding.Status status);

    @Query("""
            select f from Finding f join fetch f.project join fetch f.component join fetch f.advisory
            where f.advisory.id in :advisoryIds and f.status = deptrace.server.domain.Finding.Status.OPEN
            """)
    List<Finding> findOpenByAdvisoryIds(@Param("advisoryIds") Collection<String> advisoryIds);
}
