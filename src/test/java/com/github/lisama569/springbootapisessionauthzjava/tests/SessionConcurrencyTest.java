package com.github.lisama569.springbootapisessionauthzjava.tests;

import static org.assertj.core.api.Assertions.assertThat;

import com.github.lisama569.springbootapisessionauthzjava.domain.CredentialStatus;
import com.github.lisama569.springbootapisessionauthzjava.domain.SessionInfo;
import com.github.lisama569.springbootapisessionauthzjava.session.SessionService;
import com.github.lisama569.springbootapisessionauthzjava.tests.support.MutableClock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 同一凭证被多个线程同时续期 / 撤销时的并发安全性测试。
 */
class SessionConcurrencyTest {

    private static final Logger log = LoggerFactory.getLogger(SessionConcurrencyTest.class);

    private final MutableClock clock = new MutableClock();

    @Test
    void concurrentRenewsNeverGetLost() throws Exception {
        SessionService sessions = new SessionService(clock, 300);
        SessionInfo token = sessions.issue("alice", Duration.ofSeconds(100));

        int threads = 24;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CyclicBarrier barrier = new CyclicBarrier(threads);
        try {
            List<Future<SessionService.RenewResult>> futures = new ArrayList<>();
            for (int i = 0; i < threads; i++) {
                futures.add(pool.submit(() -> {
                    barrier.await();
                    return sessions.renew(token.token(), Duration.ofSeconds(60)).result();
                }));
            }
            for (Future<SessionService.RenewResult> f : futures) {
                assertThat(f.get()).isEqualTo(SessionService.RenewResult.RENEWED);
            }
        } finally {
            pool.shutdown();
        }

        SessionInfo finalInfo = sessions.lookup(token.token());
        // 每次续期都恰好计数一次，不多不少；到期时间为最后一次续期的 now + ttl（时钟固定）
        assertThat(finalInfo.renewedTimes()).isEqualTo(threads);
        assertThat(finalInfo.expiresAt()).isEqualTo(clock.now().plusSeconds(60));
        assertThat(sessions.statusOf(token.token())).isEqualTo(CredentialStatus.VALID);
        log.info("concurrent-renew | caller=alice | credential=VALID | renewedTimes={} | result=VALID",
                finalInfo.renewedTimes());
    }

    @Test
    void concurrentRevokesTakeEffectExactlyOnce() throws Exception {
        SessionService sessions = new SessionService(clock, 300);
        SessionInfo token = sessions.issue("bob", Duration.ofSeconds(100));

        int threads = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CyclicBarrier barrier = new CyclicBarrier(threads);
        try {
            List<Future<SessionService.RevokeResult>> futures = new ArrayList<>();
            for (int i = 0; i < threads; i++) {
                futures.add(pool.submit(() -> {
                    barrier.await();
                    return sessions.revoke(token.token()).result();
                }));
            }
            long firstRevoke = futures.stream().filter(f -> {
                try {
                    return f.get() == SessionService.RevokeResult.REVOKED;
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }).count();
            assertThat(firstRevoke).isEqualTo(1);
        } finally {
            pool.shutdown();
        }

        SessionInfo finalInfo = sessions.lookup(token.token());
        assertThat(finalInfo.revoked()).isTrue();
        assertThat(finalInfo.revokedAt()).isNotNull();
        assertThat(sessions.statusOf(token.token())).isEqualTo(CredentialStatus.REVOKED);
        log.info("concurrent-revoke | caller=bob | credential=REVOKED | result=REVOKED_EXACTLY_ONCE");
    }

    @Test
    void mixedConcurrentRenewAndRevokeNeverReopensCredential() throws Exception {
        SessionService sessions = new SessionService(clock, 300);
        SessionInfo token = sessions.issue("carol", Duration.ofSeconds(100));

        int renewers = 24;
        int revokers = 8;
        int total = renewers + revokers;
        ExecutorService pool = Executors.newFixedThreadPool(total);
        CyclicBarrier barrier = new CyclicBarrier(total);
        List<Future<SessionService.RenewResult>> renewFutures = new ArrayList<>();
        List<Future<SessionService.RevokeResult>> revokeFutures = new ArrayList<>();
        try {
            for (int i = 0; i < renewers; i++) {
                renewFutures.add(pool.submit(() -> {
                    barrier.await();
                    return sessions.renew(token.token(), Duration.ofSeconds(60)).result();
                }));
            }
            for (int i = 0; i < revokers; i++) {
                revokeFutures.add(pool.submit(() -> {
                    barrier.await();
                    return sessions.revoke(token.token()).result();
                }));
            }

            long renewed = 0;
            long renewRejected = 0;
            for (Future<SessionService.RenewResult> f : renewFutures) {
                SessionService.RenewResult r = f.get();
                assertThat(r).isIn(SessionService.RenewResult.RENEWED, SessionService.RenewResult.REVOKED);
                if (r == SessionService.RenewResult.RENEWED) {
                    renewed++;
                } else {
                    renewRejected++;
                }
            }
            long firstRevoke = 0;
            for (Future<SessionService.RevokeResult> f : revokeFutures) {
                SessionService.RevokeResult r = f.get();
                assertThat(r).isIn(SessionService.RevokeResult.REVOKED,
                        SessionService.RevokeResult.ALREADY_REVOKED);
                if (r == SessionService.RevokeResult.REVOKED) {
                    firstRevoke++;
                }
            }
            // 撤销恰好生效一次；所有续期结果都有明确归属
            assertThat(firstRevoke).isEqualTo(1);
            assertThat(renewed + renewRejected).isEqualTo(renewers);

            SessionInfo finalInfo = sessions.lookup(token.token());
            assertThat(finalInfo.revoked()).isTrue();
            // 服务端记录的成功续期次数必须与观察到 RENEWED 的次数严格一致
            assertThat(finalInfo.renewedTimes()).isEqualTo((int) renewed);
            // 撤销后任何续期都不能复活，凭证状态对后续判定稳定为 REVOKED
            assertThat(sessions.renew(token.token(), Duration.ofSeconds(60)).result())
                    .isEqualTo(SessionService.RenewResult.REVOKED);
            assertThat(sessions.statusOf(token.token())).isEqualTo(CredentialStatus.REVOKED);
            log.info("mixed-renew-revoke | caller=carol | credential=REVOKED | renewedBeforeRevoke={} | rejected={} | result=NO_REOPEN",
                    renewed, renewRejected);
        } finally {
            pool.shutdown();
        }
    }
}
