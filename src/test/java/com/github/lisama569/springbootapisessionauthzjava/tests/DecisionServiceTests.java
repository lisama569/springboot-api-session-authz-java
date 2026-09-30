package com.github.lisama569.springbootapisessionauthzjava.tests;

import static org.assertj.core.api.Assertions.assertThat;

import com.github.lisama569.springbootapisessionauthzjava.authz.AuditLog;
import com.github.lisama569.springbootapisessionauthzjava.authz.Decision;
import com.github.lisama569.springbootapisessionauthzjava.authz.DecisionOutcome;
import com.github.lisama569.springbootapisessionauthzjava.authz.DecisionService;
import com.github.lisama569.springbootapisessionauthzjava.authz.DenialReason;
import com.github.lisama569.springbootapisessionauthzjava.credential.Credential;
import com.github.lisama569.springbootapisessionauthzjava.credential.CredentialService;
import com.github.lisama569.springbootapisessionauthzjava.policy.PolicyService;
import com.github.lisama569.springbootapisessionauthzjava.support.AuditLogger;
import com.github.lisama569.springbootapisessionauthzjava.support.MutableTimeSource;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** 权限边界与失败原因区分；策略版本固定与不被追溯改写。 */
class DecisionServiceTests {

    private final MutableTimeSource clock = new MutableTimeSource(Instant.parse("2026-10-01T00:00:00Z"));
    private final CredentialService credentials = new CredentialService(clock);
    private final PolicyService policies = new PolicyService();
    private final AuditLog auditLog = new AuditLog();
    private final DecisionService decisions =
            new DecisionService(credentials, policies, clock, auditLog);

    @BeforeEach
    void clearAudit() {
        auditLog.clear();
    }

    private String tokenFor(String caller) {
        return credentials.issue(caller, Duration.ofSeconds(600)).tokenId();
    }

    @Test
    void denialReasonsAreDistinguishable() {
        String alice = tokenFor("alice"); // alice 初始策略仅有 docs:read
        String bob = tokenFor("bob");

        assertReason(decisions.decide(null, null, "docs", "read"),
                DenialReason.MISSING_CREDENTIAL);
        assertReason(decisions.decide("no-such-token", null, "docs", "read"),
                DenialReason.UNKNOWN_CREDENTIAL);

        Credential revokedCred = credentials.issue("dave", Duration.ofSeconds(600));
        credentials.revoke(revokedCred.tokenId());
        assertReason(decisions.decide(revokedCred.tokenId(), null, "docs", "read"),
                DenialReason.CREDENTIAL_REVOKED);

        Credential expiredCred = credentials.issue("erin", Duration.ofSeconds(10));
        clock.setTime(expiredCred.expiresAt());
        assertReason(decisions.decide(expiredCred.tokenId(), null, "docs", "read"),
                DenialReason.CREDENTIAL_EXPIRED);
        clock.setTime(Instant.parse("2026-10-01T00:00:00Z"));

        // 已认证但无权限（bob 无 write；alice 对 secret 无任何权限）
        assertReason(decisions.decide(alice, null, "docs", "write"),
                DenialReason.ACCESS_DENIED);
        assertReason(decisions.decide(bob, null, "secret", "read"),
                DenialReason.ACCESS_DENIED);
    }

    @Test
    void allowAndDenyDoNotDifferByResourceExistence() {
        String alice = tokenFor("alice");
        Decision allowed = decisions.decide(alice, null, "docs", "read");
        Decision deniedExistingResource = decisions.decide(alice, null, "docs", "write");
        Decision deniedUnknownResource = decisions.decide(alice, null, "does-not-exist", "read");

        AuditLogger.log(allowed);
        AuditLogger.log(deniedExistingResource);
        AuditLogger.log(deniedUnknownResource);

        assertThat(allowed.outcome()).isEqualTo(DecisionOutcome.ALLOW);
        // 对“存在但无权限”和“资源不存在”给出完全相同的原因 => 不泄露资源是否存在
        assertThat(deniedExistingResource.reason()).isEqualTo(DenialReason.ACCESS_DENIED);
        assertThat(deniedUnknownResource.reason()).isEqualTo(DenialReason.ACCESS_DENIED);
    }

    @Test
    void completedDecisionKeepsItsPolicyVersionAndIsNotRewritten() {
        long v1 = policies.current().version();
        String alice = tokenFor("alice");
        Decision underOldPolicy = decisions.decide(alice, null, "docs", "read");
        assertThat(underOldPolicy.outcome()).isEqualTo(DecisionOutcome.ALLOW);
        assertThat(underOldPolicy.policyVersion()).isEqualTo(v1);

        // 热更新为全部拒绝
        policies.replace(List.of(), null);
        long v2 = policies.current().version();

        Decision underNewPolicy = decisions.decide(alice, null, "docs", "read");
        assertThat(underNewPolicy.outcome()).isEqualTo(DecisionOutcome.DENY);
        assertThat(underNewPolicy.reason()).isEqualTo(DenialReason.ACCESS_DENIED);
        assertThat(underNewPolicy.policyVersion()).isEqualTo(v2);

        // 旧判定记录不被追溯改写
        Decision recorded = auditLog.all().get(0);
        assertThat(recorded).isEqualTo(underOldPolicy);
        assertThat(recorded.outcome()).isEqualTo(DecisionOutcome.ALLOW);
        assertThat(recorded.policyVersion()).isEqualTo(v1);
        AuditLogger.log(recorded);
        AuditLogger.log(underNewPolicy);
    }

    @Test
    void revocationTakesEffectImmediatelyWhileValidTokenStillWorks() {
        String alice = tokenFor("alice");
        assertThat(decisions.decide(alice, null, "docs", "read").outcome())
                .isEqualTo(DecisionOutcome.ALLOW);
        credentials.revoke(alice);
        Decision after = decisions.decide(alice, null, "docs", "read");
        assertThat(after.reason()).isEqualTo(DenialReason.CREDENTIAL_REVOKED);
        AuditLogger.log(after);
    }

    private static void assertReason(Decision d, DenialReason expected) {
        AuditLogger.log(d);
        assertThat(d.outcome()).isEqualTo(DecisionOutcome.DENY);
        assertThat(d.reason()).isEqualTo(expected);
    }
}
