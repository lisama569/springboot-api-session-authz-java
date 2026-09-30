package com.github.lisama569.springbootapisessionauthzjava.policy;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import org.springframework.stereotype.Service;

/**
 * 授权策略的持有者与运行期热更新。
 *
 * <p>一致性保障：
 * <ul>
 *   <li>策略以不可变 {@link Policy} 快照持有，{@link #current()} 永远返回某个完整版本，
 *       请求在判定开始时抓取一次快照，因此切换期间每个请求只能看到完整的新策略或旧策略之一，
 *       不会看到半成品；</li>
 *   <li>替换采用“先校验、后原子发布”：非法或冲突策略在校验阶段即被拒绝，
 *       当前生效策略完全不受影响；</li>
 *   <li>版本号单调递增；旧策略下已完成的判定记录自带其版本号，不会被追溯改写。</li>
 * </ul>
 */
@Service
public class PolicyService {

    private final AtomicReference<Policy> current = new AtomicReference<>();

    public PolicyService() {
        // 本地演示用初始策略
        List<PolicyRule> seed = List.of(
                new PolicyRule("alice", "docs", "read"),
                new PolicyRule("bob", "docs", "read"),
                new PolicyRule("bob", "docs", "write"));
        current.set(new Policy(1L, List.copyOf(seed)));
    }

    public Policy current() {
        return current.get();
    }

    /**
     * 原子替换策略。
     *
     * @param rules 新的完整规则集（允许空列表，即全部拒绝）
     * @param expectedVersion 若非 null，则仅当当前版本等于该值时才允许替换（乐观并发控制）
     * @return 生效后的新策略
     * @throws InvalidPolicyException 规则非法、存在冲突或版本不匹配
     */
    public Policy replace(List<PolicyRule> rules, Long expectedVersion) {
        synchronized (this) {
            Policy active = current.get();
            if (expectedVersion != null && expectedVersion.longValue() != active.version()) {
                throw new InvalidPolicyException(
                        "策略版本冲突：expected=" + expectedVersion + ", actual=" + active.version());
            }
            // 先在局部完成全部校验与构造，任何异常都不会触碰当前生效策略
            List<PolicyRule> validated = validate(rules);
            Policy next = new Policy(active.version() + 1L, validated);
            current.set(next);
            return next;
        }
    }

    /** 校验规则集：非空字段、无重复三元组。 */
    static List<PolicyRule> validate(List<PolicyRule> rules) {
        if (rules == null) {
            throw new InvalidPolicyException("规则列表不能为 null");
        }
        List<PolicyRule> normalized = new ArrayList<>(rules.size());
        Set<String> seen = new HashSet<>();
        int index = 0;
        for (PolicyRule rule : rules) {
            if (rule == null) {
                throw new InvalidPolicyException("第 " + index + " 条规则为 null");
            }
            String caller = requireText(rule.caller(), "caller", index);
            String resource = requireText(rule.resource(), "resource", index);
            String action = requireText(rule.action(), "action", index);
            String key = caller + "\u0000" + resource + "\u0000" + action;
            if (!seen.add(key)) {
                throw new InvalidPolicyException(
                        "存在重复规则（冲突）: caller=" + caller + ", resource=" + resource
                                + ", action=" + action);
            }
            normalized.add(new PolicyRule(caller, resource, action));
            index++;
        }
        return List.copyOf(normalized);
    }

    private static String requireText(String value, String field, int index) {
        if (value == null || value.isBlank()) {
            throw new InvalidPolicyException("第 " + index + " 条规则的 " + field + " 不能为空");
        }
        return value.trim();
    }
}
