package com.github.lisama569.springbootapisessionauthzjava.time;

import java.time.Instant;
import org.springframework.stereotype.Component;

/** 生产环境使用的系统时钟。 */
@Component
public class SystemTimeSource implements TimeSource {
    @Override
    public Instant now() {
        return Instant.now();
    }
}
