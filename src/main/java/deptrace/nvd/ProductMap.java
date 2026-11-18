package deptrace.nvd;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;

import deptrace.model.Coordinate;

/**
 * NVD 제품(CPE vendor:product)과 Maven 모듈의 명시적 대응표 (기본값: resources/deptrace/nvd/products.yml).
 * jar 이름에서 제품을 추측하지 않고, 표에 있는 모듈만 NVD 제품에 연결한다.
 */
public record ProductMap(List<Product> products) {

    /**
     * @param cpes      "vendor:product" 목록. 같은 제품이 시기마다 다른 vendor로 등록돼 있어 여러 개를 둔다
     * @param group     Maven groupId (정확히 일치)
     * @param artifacts artifactId 정규식 (전체 일치)
     */
    public record Product(String name, List<String> cpes, String group, String artifacts) {

        public boolean contains(Coordinate c) {
            return group.equals(c.group()) && Pattern.compile(artifacts).matcher(c.artifact()).matches();
        }
    }

    private static final ObjectMapper YAML = new ObjectMapper(new YAMLFactory())
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

    public static ProductMap defaults() {
        try (InputStream in = ProductMap.class.getResourceAsStream("/deptrace/nvd/products.yml")) {
            return YAML.readValue(in, ProductMap.class);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public static ProductMap load(Path file) {
        try {
            return YAML.readValue(Files.readString(file), ProductMap.class);
        } catch (IOException e) {
            throw new UncheckedIOException("제품 대응표를 읽을 수 없습니다: " + file, e);
        }
    }

    public Optional<Product> productOf(Coordinate c) {
        return products.stream().filter(p -> p.contains(c)).findFirst();
    }
}
