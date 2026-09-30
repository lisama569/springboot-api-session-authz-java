package com.github.lisama569.springbootapisessionauthzjava.authz;

import com.github.lisama569.springbootapisessionauthzjava.credential.Credential;
import com.github.lisama569.springbootapisessionauthzjava.credential.CredentialService;
import com.github.lisama569.springbootapisessionauthzjava.credential.CredentialStatus;
import com.github.lisama569.springbootapisessionauthzjava.policy.Policy;
import com.github.lisama569.springbootapisessionauthzjava.policy.PolicyRule;
import com.github.lisama569.springbootapisessionauthzjava.policy.PolicyService;
import com.github.lisama569.springbootapisessionauthzjava.time.TimeSource;
import java.time.Instant;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * 按调用方、资源动作与当前策略完成访问判定。
 *
 * <p>判定规则（顺序即优先级）：
 * <ol>
 *   <li>未携带凭证 → {@link DenialReason#MISSING_CREDENTIAL}；</li>
 *   <li>凭证未知 → {@link DenialReason#UNKNOWN_CREDENTIAL}；</li>
 *   <li>凭证已撤销 → {@link DenialReason#CREDENTIAL_REVOKED}（撤销优先于过期）；</li>
 *   <li>凭证已过期 → {@link DenialReason#CREDENTIAL_EXPIRED}；</li>
 *   <li>已认证但策略未授权该 (caller, resource, action) → {@link DenialReason#ACCESS_DENIED}；</li>
 *   <li>其余放行。</li>
 * </ol>
 *
 * <p>策略版本在判定开始时抓取一次，整个判定固定使用该不可变快照，
 * 因此运行期热更新不会让一次请求看到混合策略，也不会追溯改写已完成的判定。
 */
@Service
public class DecisionService {

    private static final Logger log = LoggerFactory.getLogger("AUTHZ-AUDIT");

    private final CredentialService credentialService;
    private final PolicyService policyService;
    private final TimeSource timeSource;
    private final AuditLog auditLog;

    public DecisionService(CredentialService credentialService,
                           PolicyService policyService,
                           TimeSource timeSource,
                           AuditLog auditLog) {
        this.credentialService = credentialService;
        this.policyService = policyService;
        this.timeSource = timeSource;
        this.auditLog = auditLog;
    }

    /**
     * 执行一次判定。
     *
     * @param token 凭证；null/空白表示未携带
     * @param callerHint 调用方自报身份（仅记录，不参与信任判定）
     * @param resource 目标资源
     * @param action 目标动作
     */
    public Decision decide(String token, String callerHint, String resource, String action) {
        Instant timestamp = timeSource.now();
        // 判定开始即固定策略版本
        Policy policy = policyService.current();
        long policyVersion = policy.version();
        String decisionId = UUID.randomUUID().toString();

        String caller = null;
        String tokenId = null;
        String credentialStatus = "NONE";
        DecisionOutcome outcome;
        DenialReason reason;

        if (token == null || token.isBlank()) {
            outcome = DecisionOutcome.DENY;
            reason = DenialReason.MISSING_CREDENTIAL;
        } else {
            tokenId = token.trim();
            var viewOpt = credentialService.inspect(tokenId);
            if (viewOpt.isEmpty()) {
                credentialStatus = "UNKNOWN";
                outcome = DecisionOutcome.DENY;
                reason = DenialReason.UNKNOWN_CREDENTIAL;
            } else {
                Credential credential = viewOpt.get().credential();
                CredentialStatus status = viewOpt.get().status();
                caller = credential.caller();
                credentialStatus = status.name();
                switch (status) {
                    case REVOKED -> {
                        outcome = DecisionOutcome.DENY;
                        reason = DenialReason.CREDENTIAL_REVOKED;
                    }
                    case EXPIRED -> {
                        outcome = DecisionOutcome.DENY;
                        reason = DenialReason.CREDENTIAL_EXPIRED;
                    }
                    default -> {
                        if (isPermitted(policy, caller, resource, action)) {
                            outcome = DecisionOutcome.ALLOW;
                            reason = null;
                        } else {
                            outcome = DecisionOutcome.DENY;
                            reason = DenialReason.ACCESS_DENIED;
                        }
                    }
                }
            }
        }

        Decision decision = new Decision(
                decisionId,
                timestamp,
                caller,
                resource,
                action,
                tokenId,
                credentialStatus,
                policyVersion,
                outcome,
                reason);
        auditLog.append(decision);
        log.info(
                "caller={} action={} resource={} token={} credentialStatus={} policyVersion={} "
                        + "outcome={} reason={} decisionId={} callerHint={}",
                caller, action, resource, tokenId, credentialStatus, policyVersion,
                outcome, reason, decisionId, callerHint);
        return decision;
    }

    private static boolean isPermitted(Policy policy, String caller, String resource, String action) {
        for (PolicyRule rule : policy.rules()) {
            if (rule.caller().equals(caller)
                    && rule.resource().equals(resource)
                    && rule.action().equals(action)) {
                return true;
            }
        }
        return false;
    }
}
