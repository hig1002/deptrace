package deptrace.server.rescan;

import java.time.Clock;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.batch.core.BatchStatus;
import org.springframework.batch.core.Job;
import org.springframework.batch.core.JobExecution;
import org.springframework.batch.core.JobParametersBuilder;
import org.springframework.batch.core.StepExecution;
import org.springframework.batch.core.launch.JobLauncher;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/** 매일 정해진 시각과 API 요청으로 재검사 잡을 실행한다. */
@Component
public class RescanLauncher {

    public record Summary(long executionId, String status, long componentsScanned, int newFindings) {
    }

    private static final Logger log = LoggerFactory.getLogger(RescanLauncher.class);

    private final JobLauncher launcher;
    private final Job rescanJob;
    private final Clock clock;

    public RescanLauncher(JobLauncher launcher, Job rescanJob, Clock clock) {
        this.launcher = launcher;
        this.rescanJob = rescanJob;
        this.clock = clock;
    }

    @Scheduled(cron = "${deptrace.rescan.cron}", zone = "UTC")
    public void daily() {
        Summary s = run("schedule");
        log.info("정기 재검사 완료: {}", s);
    }

    /** 잡 파라미터에 요청 시각을 넣어, 같은 날 여러 번 실행해도 별개의 실행으로 남게 한다. */
    public Summary run(String trigger) {
        try {
            // 실행마다 고유한 runId를 식별 파라미터로 준다. 요청 시각(밀리초)만 쓰면 같은 순간에 두 번 요청됐을 때
            // Spring Batch가 "이미 완료된 잡 인스턴스"로 보고 거부한다 (고정 시계 테스트에서 실제로 재현됨)
            JobExecution e = launcher.run(rescanJob, new JobParametersBuilder()
                    .addString("runId", java.util.UUID.randomUUID().toString())
                    .addString("trigger", trigger, false)
                    .addLong("requestedAt", clock.millis(), false)
                    .toJobParameters());
            long read = e.getStepExecutions().stream().filter(s -> s.getStepName().equals("rescanScan"))
                    .mapToLong(StepExecution::getReadCount).sum();
            int found = e.getExecutionContext().getInt(RescanJobConfig.NEW_FINDINGS, 0);
            if (e.getStatus() != BatchStatus.COMPLETED) {
                log.error("재검사 실패: {} {}", e.getStatus(), e.getAllFailureExceptions());
            }
            return new Summary(e.getId(), e.getStatus().name(), read, found);
        } catch (Exception ex) {
            throw new IllegalStateException("재검사를 시작할 수 없습니다: " + ex.getMessage(), ex);
        }
    }
}
