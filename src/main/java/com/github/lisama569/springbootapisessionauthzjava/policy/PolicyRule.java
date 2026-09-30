package com.github.lisama569.springbootapisessionauthzjava.policy;

/**
 * 不可变授权规则：允许某调用方对某资源执行某动作。
 */
public record PolicyRule(String caller, String resource, String action) {
}
