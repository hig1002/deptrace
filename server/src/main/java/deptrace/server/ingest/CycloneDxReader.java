package deptrace.server.ingest;

import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashSet;
import java.util.Optional;
import java.util.Set;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import deptrace.model.Coordinate;

/**
 * CycloneDX JSON에서 Maven 구성요소(purl이 pkg:maven/인 것)만 읽는다.
 * deptrace sbom이 만든 것이 기본이지만, 다른 도구의 CycloneDX도 purl만 있으면 받는다.
 */
public final class CycloneDxReader {

    public record Parsed(Set<Coordinate> components, String tool, int skipped) {
    }

    private static final ObjectMapper JSON = new ObjectMapper();

    private CycloneDxReader() {
    }

    public static Parsed read(byte[] body) {
        JsonNode bom;
        try {
            bom = JSON.readTree(body);
        } catch (IOException e) {
            throw new IllegalArgumentException("JSON이 아닙니다: " + e.getMessage());
        }
        if (!"CycloneDX".equals(bom.path("bomFormat").asText())) {
            throw new IllegalArgumentException("CycloneDX SBOM이 아닙니다 (bomFormat)");
        }
        Set<Coordinate> out = new LinkedHashSet<>();
        int skipped = 0;
        for (JsonNode c : bom.path("components")) {
            Optional<Coordinate> coordinate = fromPurl(c.path("purl").asText(""));
            if (coordinate.isPresent()) {
                out.add(coordinate.get());
            } else {
                skipped++;
            }
        }
        JsonNode tool = bom.path("metadata").path("tools").path("components").path(0);
        String toolName = tool.isMissingNode() ? null : (tool.path("name").asText("") + " " + tool.path("version").asText("")).trim();
        return new Parsed(out, toolName, skipped);
    }

    /** pkg:maven/{group}/{artifact}@{version}?qualifiers#subpath → 좌표. Maven이 아니면 empty. */
    static Optional<Coordinate> fromPurl(String purl) {
        if (!purl.startsWith("pkg:maven/")) {
            return Optional.empty();
        }
        String body = purl.substring("pkg:maven/".length());
        int cut = indexOfAny(body, '?', '#');
        if (cut >= 0) {
            body = body.substring(0, cut);
        }
        int at = body.lastIndexOf('@');
        int slash = body.indexOf('/');
        if (at < 0 || slash < 0 || slash > at) {
            return Optional.empty();
        }
        String group = decode(body.substring(0, slash));
        String artifact = decode(body.substring(slash + 1, at));
        String version = decode(body.substring(at + 1));
        if (group.isBlank() || artifact.isBlank() || version.isBlank()) {
            return Optional.empty();
        }
        return Optional.of(new Coordinate(group, artifact, version));
    }

    private static int indexOfAny(String s, char a, char b) {
        int i = s.indexOf(a);
        int j = s.indexOf(b);
        return i < 0 ? j : j < 0 ? i : Math.min(i, j);
    }

    private static String decode(String s) {
        return URLDecoder.decode(s, StandardCharsets.UTF_8);
    }
}
