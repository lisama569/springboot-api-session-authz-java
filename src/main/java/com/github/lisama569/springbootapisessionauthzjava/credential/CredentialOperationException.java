package com.github.lisama569.springbootapisessionauthzjava.credential;

/** 凭证操作非法（如续期已撤销凭证、未知凭证、非法 TTL）。 */
public class CredentialOperationException extends RuntimeException {
    public CredentialOperationException(String message) {
        super(message);
    }
}
