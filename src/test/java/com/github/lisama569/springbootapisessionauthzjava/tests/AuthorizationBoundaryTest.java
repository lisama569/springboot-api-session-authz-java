package com.github.lisama569.springbootapisessionauthzjava.tests;

import static org.assertj.core.api.Assertions.assertThat;

import com.github.lisama569.springbootapisessionauthzjava.domain.Action;
import com.github.lisama569.springbootapisessionauthzjava.domain.AuthzDecision;
import com.github.lisama569.springbootapisessionauthzjava.domain.CredentialStatus;
import com.github.lisama569.springbootapisessionauthzjava.domain.DenyReason;
import com.github.lisama569.springbootapisessionauthzjava.domain.SessionInfo;
import com.github.lisama569.springbootapisessionauthzjava.authz.AuthorizationService;
import com.github.lisama569.springbootapisessionauthzjava.policy.PolicyService;
import com.github.lisama569.springbootapisessionauthzjava.session.SessionService;
import com.github.lisama569.springbootapisessionauthzjava.tests.support.MutableClock;
import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 访问判定的权限边界测试：五种失败原因必须两两可区分，且默认拒绝（fail-closed）。
 */
class AuthorizationBoundaryTest {

    private static final Logger log = LoggerFactory.getLogger(AuthorizationBoundaryTest.class);

    private final MutableClock clock = new MutableClock();
    private final SessionService sessions = new SessionService(clock, 300);
    private final AuthorizationService authz = new AuthorizationService(sessions, new PolicyService());

    private AuthzDecision check(String token, String resource, Action action) {
        AuthzDecision d = authz.decide(token, resource, action);
        log.info("boundary | caller={} | action={} | credential={} | policyVersion={} | result={}",
                d.caller() == null ? "<anonymous>" : d.caller(),
                d.resource() + ":" + d.action(),
                d.credentialStatus(),
                d.policyVersion(),
                d.allowed() ? "ALLOW" : "DENY(" + d.denyReason() + ")");
        return d;
    }

    @Test
    void allowAndDenyBoundariesUnderSeedPolicy() {
        SessionInfo alice = sessions.issue("alice", Duration.ofSeconds(100));
        SessionInfo bob = sessions.issue("bob", Duration.ofSeconds(100));
        SessionInfo carol = sessions.issue("carol", Duration.ofSeconds(100));
        SessionInfo dave = sessions.issue("dave", Duration.ofSeconds(100));

        assertThat(check(alice.token(), "docs", Action.READ).allowed()).isTrue();
        assertThat(check(alice.token(), "docs", Action.DELETE).allowed()).isTrue();
        // bob 对 reports 只读
        assertThat(check(bob.token(), "reports", Action.READ).allowed()).isTrue();
        assertThat(check(bob.token(), "reports", Action.WRITE).denyReason())
                .isEqualTo(DenyReason.ACCESS_DENIED);
        // carol 对 docs 只读，写操作拒绝
        assertThat(check(carol.token(), "docs", Action.READ).allowed()).isTrue();
        assertThat(check(carol.token(), "docs", Action.WRITE).denyReason())
                .isEqualTo(DenyReason.ACCESS_DENIED);
        // dave 无任何规则：默认拒绝
        AuthzDecision denied = check(dave.token(), "docs", Action.READ);
        assertThat(denied.allowed()).isFalse();
        assertThat(denied.denyReason()).isEqualTo(DenyReason.ACCESS_DENIED);
        assertThat(denied.credentialStatus()).isEqualTo(CredentialStatus.VALID);
        // 未配置的资源类型同样默认拒绝
        assertThat(check(alice.token(), "secrets", Action.READ).denyReason())
                .isEqualTo(DenyReason.ACCESS_DENIED);
    }

    @Test
    void fiveFailureReasonsAreAllDistinguishable() {
        SessionInfo expiring = sessions.issue("alice", Duration.ofSeconds(10));
        SessionInfo revocable = sessions.issue("alice", Duration.ofSeconds(100));
        sessions.revoke(revocable.token());
        clock.advance(Duration.ofSeconds(10));

        AuthzDecision noCredential = check(null, "docs", Action.READ);
        assertThat(noCredential.denyReason()).isEqualTo(DenyReason.NO_CREDENTIAL);
        assertThat(noCredential.credentialStatus()).isEqualTo(CredentialStatus.ABSENT);
        assertThat(noCredential.policyVersion()).isGreaterThanOrEqualTo(1L);

        AuthzDecision invalid = check("00112233445566778899aabbccddeeff", "docs", Action.READ);
        assertThat(invalid.denyReason()).isEqualTo(DenyReason.INVALID_CREDENTIAL);
        assertThat(invalid.credentialStatus()).isEqualTo(CredentialStatus.UNKNOWN);

        AuthzDecision expired = check(expiring.token(), "docs", Action.READ);
        assertThat(expired.denyReason()).isEqualTo(DenyReason.CREDENTIAL_EXPIRED);
        assertThat(expired.credentialStatus()).isEqualTo(CredentialStatus.EXPIRED);

        AuthzDecision revoked = check(revocable.token(), "docs", Action.READ);
        assertThat(revoked.denyReason()).isEqualTo(DenyReason.CREDENTIAL_REVOKED);
        assertThat(revoked.credentialStatus()).isEqualTo(CredentialStatus.REVOKED);

        SessionInfo bob = sessions.issue("bob", Duration.ofSeconds(100));
        AuthzDecision forbidden = check(bob.token(), "docs", Action.WRITE);
        assertThat(forbidden.denyReason()).isEqualTo(DenyReason.ACCESS_DENIED);
        assertThat(forbidden.credentialStatus()).isEqualTo(CredentialStatus.VALID);
        assertThat(forbidden.caller()).isEqualTo("bob");

        // 五种原因码两两不同
        long distinctReasons = java.util.stream.Stream.of(
                        noCredential.denyReason(), invalid.denyReason(), expired.denyReason(),
                        revoked.denyReason(), forbidden.denyReason())
                .distinct().count();
        assertThat(distinctReasons).isEqualTo(5);
    }
}
