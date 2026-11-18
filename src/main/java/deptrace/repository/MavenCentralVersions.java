package deptrace.repository;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Maven Central의 maven-metadata.xml에서 배포 버전 목록을 읽는다. 하루 동안 파일로 캐시한다.
 */
public final class MavenCentralVersions implements PublishedVersions {

    private static final String BASE = "https://repo1.maven.org/maven2/";
    private static final Pattern VERSION = Pattern.compile("<version>([^<]+)</version>");
    private static final Duration TTL = Duration.ofDays(1);

    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
    private final Path cacheDir;
    private final Map<String, Optional<List<String>>> memo = new ConcurrentHashMap<>();

    public MavenCentralVersions(Path cacheDir) {
        this.cacheDir = cacheDir;
    }

    @Override
    public Optional<List<String>> versions(String module) {
        return memo.computeIfAbsent(module, this::load);
    }

    private Optional<List<String>> load(String module) {
        String[] ga = module.split(":");
        if (ga.length != 2) {
            return Optional.empty();
        }
        Path cached = cacheDir.resolve(module.replace(':', '_') + ".xml");
        try {
            String xml;
            if (Files.exists(cached) && Files.getLastModifiedTime(cached).toInstant().isAfter(Instant.now().minus(TTL))) {
                xml = Files.readString(cached);
            } else {
                URI uri = URI.create(BASE + ga[0].replace('.', '/') + "/" + ga[1] + "/maven-metadata.xml");
                HttpResponse<String> response = http.send(HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(20)).GET().build(),
                        HttpResponse.BodyHandlers.ofString());
                if (response.statusCode() != 200) {
                    return Optional.empty();
                }
                xml = response.body();
                Files.createDirectories(cacheDir);
                Files.writeString(cached, xml);
            }
            List<String> versions = new ArrayList<>();
            Matcher m = VERSION.matcher(xml);
            while (m.find()) {
                versions.add(m.group(1).trim());
            }
            return versions.isEmpty() ? Optional.empty() : Optional.of(List.copyOf(versions));
        } catch (IOException e) {
            return Optional.empty();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return Optional.empty();
        }
    }
}
