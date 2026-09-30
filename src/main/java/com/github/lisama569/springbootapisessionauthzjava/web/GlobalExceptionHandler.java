package com.github.lisama569.springbootapisessionauthzjava.web;

import com.github.lisama569.springbootapisessionauthzjava.credential.CredentialOperationException;
import com.github.lisama569.springbootapisessionauthzjava.policy.InvalidPolicyException;
import com.github.lisama569.springbootapisessionauthzjava.time.TimeSource;
import com.github.lisama569.springbootapisessionauthzjava.web.ApiDtos.ErrorResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/** 把领域异常翻译成统一错误响应，避免异常细节直接泄露。 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private final TimeSource timeSource;

    public GlobalExceptionHandler(TimeSource timeSource) {
        this.timeSource = timeSource;
    }

    /** 凭证操作非法：续期已撤销/已过期凭证、未知凭证、非法 TTL 等。 */
    @ExceptionHandler(CredentialOperationException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ErrorResponse credentialOperation(CredentialOperationException ex) {
        return new ErrorResponse(
                "credential_operation_failed",
                "INVALID_CREDENTIAL_OPERATION",
                null,
                ex.getMessage(),
                timeSource.now());
    }

    /** 策略冲突（乐观版本不匹配）→ 409；规则非法 → 400。 */
    @ExceptionHandler(InvalidPolicyException.class)
    public ResponseEntity<ErrorResponse> invalidPolicy(
            InvalidPolicyException ex) {
        boolean conflict = ex.getMessage() != null && ex.getMessage().startsWith("策略版本冲突");
        HttpStatus status = conflict ? HttpStatus.CONFLICT : HttpStatus.BAD_REQUEST;
        return ResponseEntity.status(status).body(new ErrorResponse(
                "invalid_policy",
                conflict ? "POLICY_VERSION_CONFLICT" : "INVALID_POLICY",
                null,
                ex.getMessage(),
                timeSource.now()));
    }

    /** 请求体缺失/格式错误。 */
    @ExceptionHandler(HttpMessageNotReadableException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ErrorResponse unreadable(HttpMessageNotReadableException ex) {
        return new ErrorResponse(
                "bad_request",
                "MALFORMED_REQUEST",
                null,
                "请求体格式错误或缺失",
                timeSource.now());
    }
}
