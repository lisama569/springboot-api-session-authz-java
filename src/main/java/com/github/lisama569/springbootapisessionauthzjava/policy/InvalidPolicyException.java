package com.github.lisama569.springbootapisessionauthzjava.policy;

/** 非法或冲突策略，更新将被拒绝且不影响当前生效策略。 */
public class InvalidPolicyException extends RuntimeException {
    public InvalidPolicyException(String message) {
        super(message);
    }
}
