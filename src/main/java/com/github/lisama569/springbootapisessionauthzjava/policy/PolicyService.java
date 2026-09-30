package com.github.lisama569.springbootapisessionauthzjava.policy;

import com.github.lisama569.springbootapisessionauthzjava.domain.Action;
import com.github.lisama569.springbootapisessionauthzjava.domain.Effect;
import com.github.lisama569.springbootapisessionauthzjava.domain.Policy;
import com.github.lisama569.springbootapisessionauthzjava.domain.PolicyRule;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import org.springframework.stereotype.Service;

/**
 * 授权策略服务：维护当前生效的不可变策略快照，支持原子热更新。
 *
 * 热更新保障：
 * 1. 策略以不可变快照形式存在，AtomicReference 整体替换；一次请求只读一次快照，
 *    只能看到完整的旧版本或完整的新版本，绝不会看到半成品；
 * 2. 替换采用乐观版本号：expectedVersion 必须等于当前版本，冲突（含并发覆盖）被拒绝；
 * 3. 新规则必须先通过合法性与冲突校验，任何异常都在替换前抛出，当前生效策略不受影响；
 * 4. 旧快照不被修改，旧策略下已经完成的判定不可能被追溯改写。
 */
@Service
public class PolicyService {

    private final AtomicReference<Policy> current;

    public PolicyService() {
        this.current = new AtomicReference<>(seedPolicy());
    }

    /** 返回当前生效策略的不可变快照（版本号从 1 开始单调递增）。 */
    public Policy current() {
        return current.get();
    }

    /**
     * 在给定策略快照上评估授权。无匹配规则时默认拒绝（fail-closed）。
     * 规则经过唯一键校验，同一 (调用方, 资源, 动作) 至多一条规则。
     */
    public Effect evaluate(Policy policy, String caller, String resource, Action action) {
        for (PolicyRule rule : policy.rules()) {
            if (rule.caller().equals(caller)
                    && rule.resource().equals(resource)
                    && rule.action() == action) {
                return rule.effect();
            }
        }
        return Effect.DENY;
    }

    /**
     * 原子替换策略。
     *
     * @param expectedVersion 调用方所基于的当前版本；与实际不符则拒绝
     * @param rules           新版本的完整规则集（整体替换，不做增量合并）
     * @return 替换后的新策略快照
     * @throws InvalidPolicyException 版本冲突或规则非法/冲突时抛出；当前策略保持不变
     */
    public Policy replace(long expectedVersion, List<PolicyRule> rules) {
        List<PolicyRule> validated = validate(rules);
        while (true) {
            Policy cur = current.get();
            if (expectedVersion != cur.version()) {
                throw new InvalidPolicyException(
                        "policy version conflict: expected " + expectedVersion
                                + " but current is " + cur.version());
            }
            Policy next = new Policy(cur.version() + 1, validated);
            if (current.compareAndSet(cur, next)) {
                return next;
            }
            // CAS 失败意味着并发替换先完成：回到循环重新做版本检查（必然冲突）
        }
    }

    /** 恢复到内置的版本 1 种子策略（仅供测试隔离使用）。 */
    public void resetForTesting() {
        current.set(seedPolicy());
    }

    private static List<PolicyRule> validate(List<PolicyRule> rules) {
        if (rules == null) {
            throw new InvalidPolicyException("rules must not be null");
        }
        List<PolicyRule> copy = new ArrayList<>(rules.size());
        Set<String> seen = new HashSet<>();
        for (PolicyRule rule : rules) {
            if (rule == null) {
                throw new InvalidPolicyException("rule must not be null");
            }
            if (isBlank(rule.caller()) || isBlank(rule.resource())) {
                throw new InvalidPolicyException("caller and resource must not be blank: " + rule);
            }
            if (rule.action() == null || rule.effect() == null) {
                throw new InvalidPolicyException("action and effect must not be null: " + rule);
            }
            String key = rule.caller() + "#" + rule.resource() + "#" + rule.action();
            if (!seen.add(key)) {
                throw new InvalidPolicyException(
                        "conflicting duplicate rules for (caller, resource, action): " + key);
            }
            copy.add(rule);
        }
        return List.copyOf(copy);
    }

    private static boolean isBlank(String s) {
        return s == null || s.isBlank();
    }

    /**
     * 内置初始策略（版本 1），便于本地直接验证：
     * alice 对 docs 全部动作允许、对 reports 只读；
     * bob 对 docs、reports 只读；carol 对 docs 只读；其他一切默认拒绝。
     */
    private static Policy seedPolicy() {
        List<PolicyRule> rules = List.of(
                new PolicyRule("alice", "docs", Action.READ, Effect.ALLOW),
                new PolicyRule("alice", "docs", Action.WRITE, Effect.ALLOW),
                new PolicyRule("alice", "docs", Action.DELETE, Effect.ALLOW),
                new PolicyRule("alice", "reports", Action.READ, Effect.ALLOW),
                new PolicyRule("bob", "docs", Action.READ, Effect.ALLOW),
                new PolicyRule("bob", "reports", Action.READ, Effect.ALLOW),
                new PolicyRule("carol", "docs", Action.READ, Effect.ALLOW)
        );
        return new Policy(1L, rules);
    }
}
