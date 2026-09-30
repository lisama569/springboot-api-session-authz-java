package com.github.lisama569.springbootapisessionauthzjava.clock;

import java.time.Instant;

/**
 * 鉴权专用时钟抽象，便于在测试中精确控制时间边界。
 */
public interface AuthClock {
    Instant now();
}
