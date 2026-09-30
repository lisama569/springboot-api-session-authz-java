package com.github.lisama569.springbootapisessionauthzjava.authz;

/** 可区分的失败原因。 */
public enum DenialReason {
    MISSING_CREDENTIAL,
    UNKNOWN_CREDENTIAL,
    CREDENTIAL_EXPIRED,
    CREDENTIAL_REVOKED,
    ACCESS_DENIED
}
