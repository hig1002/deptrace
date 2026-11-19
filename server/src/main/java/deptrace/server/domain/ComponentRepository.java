package deptrace.server.domain;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface ComponentRepository extends JpaRepository<Component, Long> {

    List<Component> findByPurlIn(Collection<String> purls);

    /** 어느 프로젝트든 현재 스냅샷에 들어 있는 구성요소. 재검사 대상이다. */
    @Query("""
            select distinct c from Project p join p.currentSnapshot s join s.components c
            order by c.id
            """)
    List<Component> findInUse();
}
