package com.github.lisama569.springbootapisessionauthzjava.web;

import com.github.lisama569.springbootapisessionauthzjava.policy.InvalidPolicyException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * 全局异常映射，保证管理接口的错误响应结构一致。
 * 资源接口的鉴权拒绝由拦截器直接写出，不进入这里。
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    /** 策略非法或版本冲突：调用方修正请求后可重试，当前生效策略不受影响。 */
    @ExceptionHandler(InvalidPolicyException.class)
    public ResponseEntity<ErrorResponse> handleInvalidPolicy(InvalidPolicyException ex) {
        return ResponseEntity.status(HttpStatus.CONFLICT)
                .body(new ErrorResponse("INVALID_POLICY", ex.getMessage()));
    }

    /** 请求参数非法。 */
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ErrorResponse> handleBadRequest(IllegalArgumentException ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(new ErrorResponse("BAD_REQUEST", ex.getMessage()));
    }

    /** 请求体缺失或 JSON 无法解析。 */
    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ErrorResponse> handleUnreadable(HttpMessageNotReadableException ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(new ErrorResponse("BAD_REQUEST", "malformed or missing request body"));
    }
}
