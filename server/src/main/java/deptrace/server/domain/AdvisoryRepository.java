package deptrace.server.domain;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface AdvisoryRepository extends JpaRepository<Advisory, String> {

    /** OSV ID 또는 CVE 같은 별칭으로 찾는다. */
    @Query("select a from Advisory a where a.id = :id or :id member of a.aliases")
    List<Advisory> findByIdOrAlias(@Param("id") String id);
}
