package com.github.lisama569.springbootapisessionauthzjava.tests;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.github.lisama569.springbootapisessionauthzjava.credential.Credential;
import com.github.lisama569.springbootapisessionauthzjava.credential.CredentialOperationException;
import com.github.lisama569.springbootapisessionauthzjava.credential.CredentialService;
import com.github.lisama569.springbootapisessionauthzjava.credential.CredentialStatus;
import com.github.lisama569.springbootapisessionauthzjava.support.MutableTimeSource;
import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.Test;

/** 过期时间边界：expiresAt 前一秒有效、恰好 expiresAt 即过期，结果稳定可复现。 */
class CredentialClockBoundaryTests {

    private final MutableTimeSource clock = new MutableTimeSource(Instant.parse("2026-10-01T00:00:00Z"));
    private final CredentialService credentials = new CredentialService(clock);

    @Test
    void expiryBoundaryIsDeterministicAtTheExactInstant() {
        Credential c = credentials.issue("alice", Duration.ofSeconds(10));

        clock.setTime(c.expiresAt().minusSeconds(1));
        assertThat(credentials.inspect(c.tokenId()).orElseThrow().status())
                .isEqualTo(CredentialStatus.VALID);

        // 边界：now == expiresAt => 已过期
        clock.setTime(c.expiresAt());
        assertThat(credentials.inspect(c.tokenId()).orElseThrow().status())
                .isEqualTo(CredentialStatus.EXPIRED);

        clock.setTime(c.expiresAt().plusSeconds(1));
        assertThat(credentials.inspect(c.tokenId()).orElseThrow().status())
                .isEqualTo(CredentialStatus.EXPIRED);
    }

    @Test
    void expiredCredentialCannotBeRenewedButCanBeIssuedAnew() {
        Credential c = credentials.issue("bob", Duration.ofSeconds(5));
        clock.setTime(c.expiresAt());
        assertThatThrownBy(() -> credentials.renew(c.tokenId(), Duration.ofSeconds(5)))
                .isInstanceOf(CredentialOperationException.class);

        Credential fresh = credentials.issue("bob", Duration.ofSeconds(5));
        assertThat(credentials.inspect(fresh.tokenId()).orElseThrow().status())
                .isEqualTo(CredentialStatus.VALID);
    }

    @Test
    void renewalExtendsFromRenewalInstantAndKeepsBoundaryStable() {
        Credential c = credentials.issue("carol", Duration.ofSeconds(10));
        clock.setTime(c.issuedAt().plusSeconds(8)); // 距过期 2 秒
        Credential renewed = credentials.renew(c.tokenId(), Duration.ofSeconds(10));
        assertThat(renewed.version()).isEqualTo(2L);
        assertThat(renewed.expiresAt()).isEqualTo(clock.now().plusSeconds(10));

        clock.setTime(renewed.expiresAt().minusSeconds(1));
        assertThat(credentials.inspect(c.tokenId()).orElseThrow().status())
                .isEqualTo(CredentialStatus.VALID);
        clock.setTime(renewed.expiresAt());
        assertThat(credentials.inspect(c.tokenId()).orElseThrow().status())
                .isEqualTo(CredentialStatus.EXPIRED);
    }

    @Test
    void invalidTtlIsRejected() {
        assertThatThrownBy(() -> credentials.issue("alice", Duration.ofSeconds(0)))
                .isInstanceOf(CredentialOperationException.class);
        assertThatThrownBy(() -> credentials.issue("alice", Duration.ofHours(25)))
                .isInstanceOf(CredentialOperationException.class);
    }
}
