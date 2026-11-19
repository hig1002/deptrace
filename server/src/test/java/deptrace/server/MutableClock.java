package deptrace.server;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;

/** 테스트에서 시간을 앞으로 보낼 수 있는 시계 (예외 만료 확인용). */
public class MutableClock extends Clock {

    private volatile Instant now = Instant.now();

    public void reset() {
        now = Instant.now();
    }

    public void advance(Duration d) {
        now = now.plus(d);
    }

    @Override
    public ZoneId getZone() {
        return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(ZoneId zone) {
        return this;
    }

    @Override
    public Instant instant() {
        return now;
    }
}
