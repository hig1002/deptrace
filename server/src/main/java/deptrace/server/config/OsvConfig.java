package deptrace.server.config;

import java.nio.file.Path;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import deptrace.osv.OsvClient;
import deptrace.osv.VulnerabilitySource;

/** CLI와 같은 OSV 클라이언트를 쓴다. 테스트에서는 고정 데이터를 주는 구현으로 바꾼다. */
@Configuration
public class OsvConfig {

    @Bean
    VulnerabilitySource vulnerabilitySource(DeptraceProperties props) {
        return new OsvClient(Path.of(props.osvCache()));
    }
}
