package com.github.lisama569.springbootapisessionauthzjava.domain;

/**
 * 拒绝判定的可区分原因码。
 */
public enum DenyReason {
    /** 未携带凭证 */
    NO_CREDENTIAL,
    /** 凭证无法识别 */
    INVALID_CREDENTIAL,
    /** 凭证已过期 */
    CREDENTIAL_EXPIRED,
    /** 凭证已被撤销 */
    CREDENTIAL_REVOKED,
    /** 已认证但策略未授权（默认拒绝） */
    ACCESS_DENIED
}
