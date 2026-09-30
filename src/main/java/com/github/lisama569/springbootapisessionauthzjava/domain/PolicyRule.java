package com.github.lisama569.springbootapisessionauthzjava.domain;

/**
 * 一条不可变授权规则：某调用方对某资源的某动作是允许还是拒绝。
 */
public record PolicyRule(String caller, String resource, Action action, Effect effect) {
}
