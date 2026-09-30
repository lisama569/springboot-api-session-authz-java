package com.github.lisama569.springbootapisessionauthzjava.domain;

/**
 * 对资源的操作类型，与 HTTP 方法在拦截器中映射。
 */
public enum Action {
    READ,
    WRITE,
    DELETE
}
