package deptrace.server.config;

import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("deptrace")
public record DeptraceProperties(String osvCache, String apiToken, Rescan rescan, Notification notification,
                                 Exceptions exceptions) {

    /**
     * @param maxDuration    예외를 한 번에 인정하는 최대 기간. 길게 잡으면 사실상 영구 무시 목록이 된다
     * @param expiringWindow 이 기간 안에 만료되는 예외를 "곧 만료"로 보여준다
     */
    public record Exceptions(Duration maxDuration, Duration expiringWindow) {
    }

    public record Rescan(String cron, int chunkSize, Duration freshFor) {
    }

    /** notify는 Object.notify()와 이름이 겹쳐 레코드 구성요소로 쓸 수 없다. */
    public record Notification(String webhookUrl) {
    }
}
