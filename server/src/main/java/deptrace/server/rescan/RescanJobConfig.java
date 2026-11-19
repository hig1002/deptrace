package deptrace.server.rescan;

import java.util.ArrayList;
import java.util.List;

import org.springframework.batch.core.Job;
import org.springframework.batch.core.Step;
import org.springframework.batch.core.configuration.annotation.StepScope;
import org.springframework.batch.core.job.builder.JobBuilder;
import org.springframework.batch.core.launch.support.RunIdIncrementer;
import org.springframework.batch.core.repository.JobRepository;
import org.springframework.batch.core.step.builder.StepBuilder;
import org.springframework.batch.item.database.JpaPagingItemReader;
import org.springframework.batch.item.database.builder.JpaPagingItemReaderBuilder;
import org.springframework.batch.repeat.RepeatStatus;
import org.springframework.batch.support.transaction.ResourcelessTransactionManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.transaction.PlatformTransactionManager;

import jakarta.persistence.EntityManagerFactory;

import deptrace.server.config.DeptraceProperties;
import deptrace.server.domain.Component;
import deptrace.server.domain.Finding;
import deptrace.server.domain.Project;
import deptrace.server.domain.ProjectRepository;
import deptrace.server.notify.Notifier;
import deptrace.server.scan.FindingReconciler;
import deptrace.server.scan.ScanService;

/**
 * 매일 재검사. 코드가 바뀌지 않아도 새 권고가 공개되면 잡아낸다 (경매톡 guava 사례: 점검 8일 뒤 공개된 HIGH).
 *
 * <ol>
 *   <li>scan: 모든 프로젝트의 현재 스냅샷에 있는 구성요소를 중복 없이 청크로 읽어 OSV에 다시 묻는다.
 *       프로젝트가 100개여도 같은 버전은 한 번만 조회한다.</li>
 *   <li>reconcile: 프로젝트마다 발견 상태를 맞추고, 새로 열린 것을 알린다.</li>
 * </ol>
 */
@Configuration
public class RescanJobConfig {

    public static final String JOB = "rescanJob";
    public static final String NEW_FINDINGS = "newFindings";

    @Bean
    Job rescanJob(JobRepository repository, Step rescanScanStep, Step rescanReconcileStep) {
        return new JobBuilder(JOB, repository)
                .incrementer(new RunIdIncrementer())
                .start(rescanScanStep)
                .next(rescanReconcileStep)
                .build();
    }

    /**
     * 청크 트랜잭션은 리소스 없는 트랜잭션 매니저로 둔다. OSV 조회(네트워크)가 청크 안에서 일어나는데,
     * JPA 트랜잭션으로 묶으면 조회하는 동안 DB 커넥션을 잡고 있게 된다. 저장은 ScanService.Writer가 자기 트랜잭션으로 하고,
     * 저장이 멱등(같은 결과를 다시 써도 같음)이라 청크를 다시 실행해도 안전하다.
     */
    @Bean
    Step rescanScanStep(JobRepository repository, JpaPagingItemReader<Component> inUseComponentReader, ScanService scanner,
                        DeptraceProperties props) {
        return new StepBuilder("rescanScan", repository)
                .<Component, Component>chunk(props.rescan().chunkSize(), new ResourcelessTransactionManager())
                .reader(inUseComponentReader)
                .writer(chunk -> scanner.scan(new ArrayList<>(chunk.getItems())))
                .build();
    }

    /** 리더는 읽은 위치를 상태로 가진다. 실행마다 새로 만들도록 스텝 범위로 둔다. */
    @Bean
    @StepScope
    JpaPagingItemReader<Component> inUseComponentReader(EntityManagerFactory emf, DeptraceProperties props) {
        return new JpaPagingItemReaderBuilder<Component>()
                .name("inUseComponentReader")
                .entityManagerFactory(emf)
                .queryString("select distinct c from Project p join p.currentSnapshot s join s.components c order by c.id")
                .pageSize(props.rescan().chunkSize())
                .saveState(true)
                .build();
    }

    @Bean
    Step rescanReconcileStep(JobRepository repository, PlatformTransactionManager transactionManager,
                             ProjectRepository projects, FindingReconciler reconciler, Notifier notifier) {
        return new StepBuilder("rescanReconcile", repository)
                .tasklet((contribution, context) -> {
                    List<Notifier.Alert> alerts = new ArrayList<>();
                    for (Project p : projects.findAll()) {
                        if (p.getCurrentSnapshot() != null) {
                            alerts.addAll(reconciler.reconcile(p, Finding.DetectedBy.RESCAN).alerts());
                        }
                    }
                    notifier.send(alerts);
                    context.getStepContext().getStepExecution().getJobExecution().getExecutionContext()
                            .putInt(NEW_FINDINGS, alerts.size());
                    return RepeatStatus.FINISHED;
                }, new ResourcelessTransactionManager())
                .build();
    }
}
