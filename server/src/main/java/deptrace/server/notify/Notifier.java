package deptrace.server.notify;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;

import deptrace.server.config.DeptraceProperties;

/**
 * 새 발견을 알린다. 웹훅 URL이 있으면 JSON으로 보내고(Slack incoming webhook 등), 항상 로그도 남긴다.
 * 알림 실패가 재검사 자체를 실패시키지 않도록 예외를 삼킨다.
 */
@Component
public class Notifier {

    /** 알림 한 건: 프로젝트와 새로 걸린 권고 요약. */
    /** event: NEW(새 발견), REOPENED(해결됐다가 다시 나타남), ACCEPTANCE_ENDED(예외 만료·철회로 다시 조치 대상). */
    public record Alert(String project, String component, String advisory, String severity, String detectedBy, String event) {

        String label() {
            return switch (event) {
                case "REOPENED" -> "다시 나타남";
                case "ACCEPTANCE_ENDED" -> "예외 종료";
                default -> "새 발견";
            };
        }
    }

    private static final Logger log = LoggerFactory.getLogger(Notifier.class);
    private static final ObjectMapper JSON = new ObjectMapper();

    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
    private final String webhookUrl;

    public Notifier(DeptraceProperties props) {
        this.webhookUrl = props.notification() == null ? null : props.notification().webhookUrl();
    }

    public void send(List<Alert> alerts) {
        if (alerts.isEmpty()) {
            return;
        }
        alerts.forEach(a -> log.warn("{} [{}] {} {} ({}, {})", a.label(), a.project(), a.component(), a.advisory(), a.severity(), a.detectedBy()));
        if (webhookUrl == null || webhookUrl.isBlank()) {
            return;
        }
        try {
            StringBuilder text = new StringBuilder("DepTrace: 조치가 필요한 취약점 " + alerts.size() + "건\n");
            alerts.stream().limit(20).forEach(a -> text.append("• ").append(a.label()).append(" [").append(a.project()).append("] ")
                    .append(a.component()).append(" — ").append(a.advisory()).append(" (").append(a.severity()).append(")\n"));
            String body = JSON.writeValueAsString(Map.of("text", text.toString(), "alerts", alerts));
            HttpResponse<Void> r = http.send(HttpRequest.newBuilder(URI.create(webhookUrl)).timeout(Duration.ofSeconds(10))
                    .header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(body)).build(),
                    HttpResponse.BodyHandlers.discarding());
            if (r.statusCode() >= 300) {
                log.error("알림 웹훅 응답 {}", r.statusCode());
            }
        } catch (Exception e) {
            log.error("알림 웹훅 실패: {}", e.toString());
        }
    }
}
