package com.github.lisama569.springbootapisessionauthzjava.tests;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.github.lisama569.springbootapisessionauthzjava.credential.Credential;
import com.github.lisama569.springbootapisessionauthzjava.credential.CredentialOperationException;
import com.github.lisama569.springbootapisessionauthzjava.credential.CredentialService;
import com.github.lisama569.springbootapisessionauthzjava.support.AuditLogger;
import com.github.lisama569.springbootapisessionauthzjava.support.MutableTimeSource;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

/** 并发续期与撤销：不重复生效、不越权放行、有效凭证不被误判失效。 */
class CredentialConcurrencyTests {

    private final MutableTimeSource clock = new MutableTimeSource(Instant.parse("2026-10-01T00:00:00Z"));
    private final CredentialService credentials = new CredentialService(clock);

    @Test
    void concurrentRenewalsAreSerializedWithoutLostOrDuplicateEffect() throws Exception {
        Credential issued = credentials.issue("alice", Duration.ofSeconds(60));
        int threads = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<?>> futures = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            futures.add(pool.submit(() -> {
                start.await();
                credentials.renew(issued.tokenId(), Duration.ofSeconds(60));
                return null;
            }));
        }
        start.countDown();
        for (Future<?> f : futures) {
            f.get(10, TimeUnit.SECONDS);
        }
        pool.shutdown();

        Credential after = credentials.inspect(issued.tokenId()).orElseThrow().credential();
        AuditLogger.log(
                new com.github.lisama569.springbootapisessionauthzjava.authz.Decision(
                        "renew-stress", clock.now(), after.caller(), "credential", "renew",
                        after.tokenId(), "VALID", null,
                        com.github.lisama569.springbootapisessionauthzjava.authz.DecisionOutcome.ALLOW,
                        null));
        // 16 次续期全部串行提交：版本恰好 +16，没有丢失更新也没有重复计数
        assertThat(after.version()).isEqualTo(1L + threads);
        // 每次续期 issuedAt 都被推进到时钟当前时刻
        assertThat(after.issuedAt()).isEqualTo(clock.now());
        assertThat(credentials.inspect(issued.tokenId()).orElseThrow().status())
                .isEqualTo(com.github.lisama569.springbootapisessionauthzjava.credential.CredentialStatus.VALID);
    }

    @Test
    void renewRacingAgainstRevokeNeverReopensARevokedCredential() throws Exception {
        Credential issued = credentials.issue("bob", Duration.ofSeconds(300));
        int threads = 32;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger renewed = new AtomicInteger();
        AtomicInteger rejected = new AtomicInteger();
        List<Future<?>> futures = new ArrayList<>();

        for (int i = 0; i < threads - 1; i++) {
            futures.add(pool.submit(() -> {
                start.await();
                try {
                    credentials.renew(issued.tokenId(), Duration.ofSeconds(300));
                    renewed.incrementAndGet();
                } catch (CredentialOperationException e) {
                    rejected.incrementAndGet();
                }
                return null;
            }));
        }
        futures.add(pool.submit(() -> {
            start.await();
            credentials.revoke(issued.tokenId());
            return null;
        }));

        start.countDown();
        for (Future<?> f : futures) {
            f.get(10, TimeUnit.SECONDS);
        }
        pool.shutdown();

        AuditLogger.banner("revoke-vs-renew: renewed=" + renewed.get() + " rejected=" + rejected.get());
        // 最终凭证一定处于已撤销状态
        var view = credentials.inspect(issued.tokenId()).orElseThrow();
        assertThat(view.credential().revoked()).isTrue();
        assertThat(view.status())
                .isEqualTo(com.github.lisama569.springbootapisessionauthzjava.credential.CredentialStatus.REVOKED);
        // 撤销前的续期可能成功，撤销后的续期必须全部失败；二者数量互补
        assertThat(renewed.get() + rejected.get()).isEqualTo(threads - 1);
        assertThat(reducedVersionConsistent(view.credential(), renewed.get())).isTrue();

        // 撤销之后再续期必须被拒绝，无法复活
        assertThatThrownBy(() -> credentials.renew(issued.tokenId(), Duration.ofSeconds(300)))
                .isInstanceOf(CredentialOperationException.class);
        // 撤销幂等
        assertThat(credentials.revoke(issued.tokenId())).isFalse();
    }

    /** 版本号增量只可能来自成功的续期次数，证明没有重复生效。 */
    private static boolean reducedVersionConsistent(Credential c, int renewedCount) {
        return c.version() == 1L + renewedCount;
    }
}
