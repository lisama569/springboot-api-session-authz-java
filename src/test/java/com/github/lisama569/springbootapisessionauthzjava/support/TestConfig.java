package com.github.lisama569.springbootapisessionauthzjava.support;

import com.github.lisama569.springbootapisessionauthzjava.time.TimeSource;
import java.time.Instant;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

/** 测试配置：以固定起点的可控时钟覆盖系统时钟。 */
@TestConfiguration
public class TestConfig {

    public static final Instant EPOCH = Instant.parse("2026-10-01T00:00:00Z");

    @Bean
    @Primary
    public MutableTimeSource mutableTimeSource() {
        return new MutableTimeSource(EPOCH);
    }
}
