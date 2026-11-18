package deptrace.license;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import deptrace.model.Coordinate;

/** 좌표의 POM 원문을 가져온다. */
public interface PomSource {

    Optional<String> pom(Coordinate coordinate);

    /**
     * Maven Central에서 POM을 받는다. 배포된 POM은 바뀌지 않으므로 만료 없이 파일로 캐시한다.
     * 없는 POM(404)도 기록해 두어 같은 실행 안에서 다시 묻지 않는다.
     */
    final class MavenCentral implements PomSource {

        private static final String BASE = "https://repo1.maven.org/maven2/";

        private final HttpClient http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();
        private final Path cacheDir;
        private final Map<Coordinate, Optional<String>> memo = new ConcurrentHashMap<>();
        private int fetched;
        private int cached;

        public MavenCentral(Path cacheDir) {
            this.cacheDir = cacheDir;
        }

        @Override
        public Optional<String> pom(Coordinate c) {
            return memo.computeIfAbsent(c, this::load);
        }

        public String stats() {
            return "POM 다운로드 " + fetched + "건, 캐시 사용 " + cached + "건";
        }

        private Optional<String> load(Coordinate c) {
            String relative = c.group().replace('.', '/') + "/" + c.artifact() + "/" + c.version() + "/"
                    + c.artifact() + "-" + c.version() + ".pom";
            Path file = cacheDir.resolve(relative);
            try {
                if (Files.exists(file)) {
                    synchronized (this) {
                        cached++;
                    }
                    return Optional.of(Files.readString(file));
                }
                HttpResponse<String> response = http.send(
                        HttpRequest.newBuilder(URI.create(BASE + relative)).timeout(Duration.ofSeconds(20)).GET().build(),
                        HttpResponse.BodyHandlers.ofString());
                if (response.statusCode() != 200) {
                    return Optional.empty();
                }
                Files.createDirectories(file.getParent());
                Files.writeString(file, response.body());
                synchronized (this) {
                    fetched++;
                }
                return Optional.of(response.body());
            } catch (IOException e) {
                return Optional.empty();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return Optional.empty();
            }
        }
    }
}
