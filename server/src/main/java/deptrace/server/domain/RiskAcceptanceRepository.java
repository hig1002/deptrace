package deptrace.server.domain;

import java.time.LocalDate;
import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface RiskAcceptanceRepository extends JpaRepository<RiskAcceptance, Long> {

    List<RiskAcceptance> findByProjectOrderByCreatedAtDesc(Project project);

    /** 철회되지 않았고 오늘까지 유효한 예외. */
    @Query("select r from RiskAcceptance r where r.project = :project and r.revokedAt is null and r.expiresOn >= :today")
    List<RiskAcceptance> findActive(@Param("project") Project project, @Param("today") LocalDate today);

    /** 곧 만료되는 예외 (모든 프로젝트). 만료 전에 다시 볼 수 있게 미리 알린다. */
    @Query("""
            select r from RiskAcceptance r join fetch r.project
            where r.revokedAt is null and r.expiresOn >= :today and r.expiresOn <= :until
            order by r.expiresOn
            """)
    List<RiskAcceptance> findExpiringBetween(@Param("today") LocalDate today, @Param("until") LocalDate until);
}
