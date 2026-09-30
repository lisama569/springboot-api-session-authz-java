package com.github.lisama569.springbootapisessionauthzjava.support;

import com.github.lisama569.springbootapisessionauthzjava.time.TimeSource;
import java.time.Instant;

/** 测试用可控时钟，支持自由设置/推进时间，复现过期边界。 */
public class MutableTimeSource implements TimeSource {

    private volatile Instant current;

    public MutableTimeSource(Instant initial) {
        this.current = initial;
    }

    @Override
    public Instant now() {
        return current;
    }

    public void setTime(Instant time) {
        this.current = time;
    }

    public void advanceSeconds(long seconds) {
        this.current = current.plusSeconds(seconds);
    }
}
