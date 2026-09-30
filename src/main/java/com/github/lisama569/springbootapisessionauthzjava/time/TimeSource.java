package com.github.lisama569.springbootapisessionauthzjava.time;

import java.time.Instant;

/** 可替换的时钟来源，便于在测试中稳定复现时间边界。 */
public interface TimeSource {
    Instant now();
}
