package com.github.lisama569.springbootapisessionauthzjava.web;

/**
 * 统一错误响应体：对鉴权类错误只返回稳定的原因码，不暴露资源是否存在。
 */
public record ErrorResponse(String error, String message) {
}
