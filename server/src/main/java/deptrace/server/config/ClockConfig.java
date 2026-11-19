package deptrace.server.config;

import java.time.Clock;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** 시각을 주입받아 테스트에서 고정·이동할 수 있게 한다 (만료·최근 조회 판정). */
@Configuration
public class ClockConfig {

    @Bean
    Clock clock() {
        return Clock.systemUTC();
    }
}
