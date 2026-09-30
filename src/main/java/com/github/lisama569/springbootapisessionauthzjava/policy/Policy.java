package com.github.lisama569.springbootapisessionauthzjava.policy;

import java.util.List;

/**
 * 不可变授权策略快照。每个请求只能看到完整的某一版策略。
 *
 * @param version 单调递增的策略版本号
 * @param rules 完整规则列表
 */
public record Policy(long version, List<PolicyRule> rules) {
}
