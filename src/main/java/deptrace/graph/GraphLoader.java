package deptrace.graph;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Stream;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

/** init script가 만든 구성별 JSON(build/deptrace/*.json)을 읽는다. */
public final class GraphLoader {

    /** 결과 판정의 기준 구성. bootJar에 실제로 들어가는 구성이 우선이다. */
    private static final List<String> PRIMARY_PREFERENCE = List.of("productionRuntimeClasspath", "runtimeClasspath", "maven:runtime");

    private final ObjectMapper json = new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

    public List<ResolvedGraph> loadDirectory(Path dir) {
        try (Stream<Path> files = Files.list(dir)) {
            List<ResolvedGraph> graphs = files
                    .filter(p -> p.getFileName().toString().endsWith(".json"))
                    .sorted()
                    .map(this::load)
                    .filter(g -> g != null)
                    .toList();
            if (graphs.isEmpty()) {
                throw new IllegalArgumentException("그래프 파일이 없습니다: " + dir);
            }
            return graphs;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public ResolvedGraph load(Path file) {
        try {
            GraphExport export = json.readValue(file.toFile(), GraphExport.class);
            if (export.format() == null || !export.format().startsWith("deptrace-graph/")) {
                return null;
            }
            return ResolvedGraph.of(export);
        } catch (IOException e) {
            throw new UncheckedIOException("그래프 파일을 읽을 수 없습니다: " + file, e);
        }
    }

    public static ResolvedGraph primary(List<ResolvedGraph> graphs) {
        return graphs.stream()
                .min(Comparator.comparingInt(g -> {
                    int i = PRIMARY_PREFERENCE.indexOf(g.configuration());
                    return i < 0 ? Integer.MAX_VALUE : i;
                }))
                .orElseThrow();
    }
}
