package com.github.lisama569.springbootapisessionauthzjava.authz;

import com.github.lisama569.springbootapisessionauthzjava.domain.Action;
import com.github.lisama569.springbootapisessionauthzjava.domain.AuthzDecision;
import com.github.lisama569.springbootapisessionauthzjava.domain.CredentialStatus;
import com.github.lisama569.springbootapisessionauthzjava.domain.DenyReason;
import com.github.lisama569.springbootapisessionauthzjava.domain.Effect;
import com.github.lisama569.springbootapisessionauthzjava.domain.Policy;
import com.github.lisama569.springbootapisessionauthzjava.domain.SessionInfo;
import com.github.lisama569.springbootapisessionauthzjava.policy.PolicyService;
import com.github.lisama569.springbootapisessionauthzjava.session.SessionService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * 访问判定服务：串联凭证校验与策略判定，并输出结构化、可解释的判定结果。
 *
 * <p>一次判定只读取一次策略快照，因此即使判定期间发生热更新，本次判定也只会使用
 * 完整的同一版本策略，结果稳定可复现。
 */
@Service
public class AuthorizationService {

    private static final Logger log = LoggerFactory.getLogger(AuthorizationService.class);

    private final SessionService sessions;
    private final PolicyService policies;

    public AuthorizationService(SessionService sessions, PolicyService policies) {
        this.sessions = sessions;
        this.policies = policies;
    }

    /**
     * 对一次资源访问进行判定。
     *
     * @param token    请求携带的凭证（Authorization 头内容），可为 null
     * @param resource 资源类型
     * @param action   请求动作
     */
    public AuthzDecision decide(String token, String resource, Action action) {
        Policy policy = policies.current();
        CredentialStatus status = sessions.statusOf(token);
        AuthzDecision decision = switch (status) {
            case ABSENT -> deny(DenyReason.NO_CREDENTIAL, null, resource, action, status, policy.version());
            case UNKNOWN -> deny(DenyReason.INVALID_CREDENTIAL, null, resource, action, status, policy.version());
            case EXPIRED -> deny(DenyReason.CREDENTIAL_EXPIRED, null, resource, action, status, policy.version());
            case REVOKED -> deny(DenyReason.CREDENTIAL_REVOKED, null, resource, action, status, policy.version());
            case VALID -> {
                SessionInfo info = sessions.lookup(token);
                String caller = info == null ? null : info.caller();
                if (policies.evaluate(policy, caller, resource, action) == Effect.ALLOW) {
                    yield new AuthzDecision(true, null, caller, action, resource, status, policy.version());
                }
                yield deny(DenyReason.ACCESS_DENIED, caller, resource, action, status, policy.version());
            }
        };
        log.info("authorization decision | caller={} | action={} | resource={} | credential={} | policyVersion={} | result={}",
                decision.caller() == null ? "<anonymous>" : decision.caller(),
                decision.action(),
                decision.resource(),
                decision.credentialStatus(),
                decision.policyVersion(),
                decision.allowed() ? "ALLOW" : "DENY(" + decision.denyReason() + ")");
        return decision;
    }

    private static AuthzDecision deny(DenyReason reason, String caller, String resource, Action action,
                                      CredentialStatus status, long policyVersion) {
        return new AuthzDecision(false, reason, caller, action, resource, status, policyVersion);
    }
}
