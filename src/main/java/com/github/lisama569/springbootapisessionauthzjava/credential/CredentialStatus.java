package com.github.lisama569.springbootapisessionauthzjava.credential;

/** 凭证在某一时刻被解释出的状态，失败原因可被调用方区分。 */
public enum CredentialStatus {
    VALID,
    EXPIRED,
    REVOKED
}
