package com.github.lisama569.springbootapisessionauthzjava.policy;

/**
 * 策略非法或与当前版本冲突时抛出；抛出后当前生效策略不受影响。
 */
public class InvalidPolicyException extends RuntimeException {
    public InvalidPolicyException(String message) {
        super(message);
    }
}
