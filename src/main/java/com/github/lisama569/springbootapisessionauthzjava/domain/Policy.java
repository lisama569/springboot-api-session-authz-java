package com.github.lisama569.springbootapisessionauthzjava.domain;

import java.util.List;

/**
 * 一份不可变授权策略快照。策略版本单调递增，每次热更新产生一份全新快照。
 */
public record Policy(long version, List<PolicyRule> rules) {
}
