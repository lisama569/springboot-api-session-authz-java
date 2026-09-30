package com.github.lisama569.springbootapisessionauthzjava.tests;

import static org.assertj.core.api.Assertions.assertThat;

import com.github.lisama569.springbootapisessionauthzjava.domain.CredentialStatus;
import com.github.lisama569.springbootapisessionauthzjava.domain.SessionInfo;
import com.github.lisama569.springbootapisessionauthzjava.session.SessionService;
import com.github.lisama569.springbootapisessionauthzjava.tests.support.MutableClock;
import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 凭证生命周期的时钟边界测试：签发前一刻、到期前一刻、到期时刻、到期之后。
 * 时钟可控，因此结果稳定可复现。
 */
class SessionClockBoundaryTest {

    private static final Logger log = LoggerFactory.getLogger(SessionClockBoundaryTest.class);

    private final MutableClock clock = new MutableClock();

    @Test
    void expiryBoundaryIsStableAndReproducible() {
        SessionService sessions = new SessionService(clock, 300);
        SessionInfo token = sessions.issue("alice", Duration.ofSeconds(10));

        // 到期前一刻：有效
        clock.advance(Duration.ofSeconds(9));
        assertThat(sessions.statusOf(token.token())).isEqualTo(CredentialStatus.VALID);
        log.info("clock-boundary | caller=alice | action=READ | credential=VALID | result=VALID | t=-1s");

        // 到期时刻（now == expiresAt）：按约定立即视为过期，边界确定
        clock.advance(Duration.ofSeconds(1));
        assertThat(sessions.statusOf(token.token())).isEqualTo(CredentialStatus.EXPIRED);
        log.info("clock-boundary | caller=alice | action=READ | credential=EXPIRED | result=DENY(CREDENTIAL_EXPIRED) | t=0s");

        // 再推进：仍然过期，判定不会随时间抖动
        clock.advance(Duration.ofMinutes(10));
        assertThat(sessions.statusOf(token.token())).isEqualTo(CredentialStatus.EXPIRED);
        log.info("clock-boundary | caller=alice | action=READ | credential=EXPIRED | result=DENY(CREDENTIAL_EXPIRED) | t=+600s");

        // 回拨到到期前：重新有效（受控时钟下语义一致，无缓存脏状态）
        clock.set(MutableClock.BASE.plusSeconds(5));
        assertThat(sessions.statusOf(token.token())).isEqualTo(CredentialStatus.VALID);
        log.info("clock-boundary | caller=alice | action=READ | credential=VALID | result=VALID | t=-5s(rewound)");
    }

    @Test
    void expiredCredentialCannotBeRenewed() {
        SessionService sessions = new SessionService(clock, 300);
        SessionInfo token = sessions.issue("bob", Duration.ofSeconds(10));

        clock.advance(Duration.ofSeconds(10));
        assertThat(sessions.statusOf(token.token())).isEqualTo(CredentialStatus.EXPIRED);

        SessionService.RenewOutcome outcome = sessions.renew(token.token(), Duration.ofSeconds(60));
        assertThat(outcome.result()).isEqualTo(SessionService.RenewResult.EXPIRED);
        assertThat(sessions.statusOf(token.token())).isEqualTo(CredentialStatus.EXPIRED);
        log.info("clock-boundary | caller=bob | action=RENEW | credential=EXPIRED | result=DENY(EXPIRED)");
    }

    @Test
    void revokedCredentialStaysRevokedWhenTimeMoves() {
        SessionService sessions = new SessionService(clock, 300);
        SessionInfo token = sessions.issue("carol", Duration.ofSeconds(10));

        assertThat(sessions.revoke(token.token()).result())
                .isEqualTo(SessionService.RevokeResult.REVOKED);
        // 撤销优先于过期：即使推进到远超到期时间，状态仍是 REVOKED，原因可区分
        clock.advance(Duration.ofMinutes(30));
        assertThat(sessions.statusOf(token.token())).isEqualTo(CredentialStatus.REVOKED);
        assertThat(sessions.renew(token.token(), Duration.ofSeconds(60)).result())
                .isEqualTo(SessionService.RenewResult.REVOKED);
        log.info("clock-boundary | caller=carol | action=RENEW | credential=REVOKED | result=DENY(REVOKED) | t=+1800s");
    }

    @Test
    void absentAndUnknownCredentialsAreDistinguished() {
        SessionService sessions = new SessionService(clock, 300);
        assertThat(sessions.statusOf(null)).isEqualTo(CredentialStatus.ABSENT);
        assertThat(sessions.statusOf("deadbeef")).isEqualTo(CredentialStatus.UNKNOWN);
        log.info("clock-boundary | caller=<anonymous> | action=READ | credential=ABSENT | result=DENY(NO_CREDENTIAL)");
        log.info("clock-boundary | caller=<anonymous> | action=READ | credential=UNKNOWN | result=DENY(INVALID_CREDENTIAL)");
    }
}
