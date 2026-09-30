package com.github.lisama569.springbootapisessionauthzjava.domain;

/**
 * 一次访问判定的不可变结果。
 *
 * @param allowed          是否放行
 * @param denyReason       拒绝原因（放行时为 null）
 * @param caller           调用方（无法认证时为 null）
 * @param action           请求动作
 * @param resource         请求资源
 * @param credentialStatus 凭证状态
 * @param policyVersion    做判定时所见的策略版本（未进入策略判定时为 -1）
 */
public record AuthzDecision(boolean allowed, DenyReason denyReason, String caller, Action action,
                            String resource, CredentialStatus credentialStatus, long policyVersion) {
}
