package com.github.lisama569.springbootapisessionauthzjava.domain;

/**
 * 凭证在一次访问判定时刻所处的状态。
 */
public enum CredentialStatus {
    /** 请求未携带凭证 */
    ABSENT,
    /** 携带了无法识别的凭证 */
    UNKNOWN,
    /** 凭证有效 */
    VALID,
    /** 凭证已过期 */
    EXPIRED,
    /** 凭证已被撤销 */
    REVOKED
}
