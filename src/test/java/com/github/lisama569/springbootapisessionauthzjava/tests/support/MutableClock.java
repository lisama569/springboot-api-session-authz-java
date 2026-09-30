package com.github.lisama569.springbootapisessionauthzjava.tests.support;

import com.github.lisama569.springbootapisessionauthzjava.clock.AuthClock;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicReference;

/**
 * 测试用可控时钟：时间只在显式调用时前进，便于稳定复现过期边界。
 */
public class MutableClock implements AuthClock {

    /** 固定的基准时间，避免依赖真实系统时间。 */
    public static final Instant BASE = Instant.parse("2026-10-01T00:00:00Z");

    private final AtomicReference<Instant> now = new AtomicReference<>(BASE);

    @Override
    public Instant now() {
        return now.get();
    }

    public void set(Instant instant) {
        now.set(instant);
    }

    public void advance(Duration duration) {
        now.updateAndGet(t -> t.plus(duration));
    }
}
