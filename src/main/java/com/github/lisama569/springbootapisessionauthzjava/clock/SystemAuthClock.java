package com.github.lisama569.springbootapisessionauthzjava.clock;

import java.time.Instant;
import org.springframework.stereotype.Component;

/**
 * 生产环境时钟：直接读取系统 UTC 时间。
 */
@Component
public class SystemAuthClock implements AuthClock {
    @Override
    public Instant now() {
        return Instant.now();
    }
}
