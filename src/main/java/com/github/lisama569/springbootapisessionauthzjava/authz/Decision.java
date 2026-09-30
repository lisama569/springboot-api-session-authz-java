package com.github.lisama569.springbootapisessionauthzjava.authz;

import java.time.Instant;

/**
 * 一次访问判定的不可变记录。判定时刻所看到的策略版本被固定，
 * 后续策略更新不会追溯改写已完成的判定。
 */
public record Decision(
        String decisionId,
        Instant timestamp,
        String caller,
        String resource,
        String action,
        String tokenId,
        String credentialStatus,
        Long policyVersion,
        DecisionOutcome outcome,
        DenialReason reason) {
}
