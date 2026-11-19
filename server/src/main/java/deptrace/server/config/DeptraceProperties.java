package deptrace.server.config;

import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("deptrace")
public record DeptraceProperties(String osvCache, String apiToken, Rescan rescan, Notification notification) {

    public record Rescan(String cron, int chunkSize, Duration freshFor) {
    }

    /** notify는 Object.notify()와 이름이 겹쳐 레코드 구성요소로 쓸 수 없다. */
    public record Notification(String webhookUrl) {
    }
}
