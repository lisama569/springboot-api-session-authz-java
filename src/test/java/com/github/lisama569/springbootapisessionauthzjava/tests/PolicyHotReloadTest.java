package com.github.lisama569.springbootapisessionauthzjava.tests;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.github.lisama569.springbootapisessionauthzjava.domain.Action;
import com.github.lisama569.springbootapisessionauthzjava.domain.Effect;
import com.github.lisama569.springbootapisessionauthzjava.domain.Policy;
import com.github.lisama569.springbootapisessionauthzjava.domain.PolicyRule;
import com.github.lisama569.springbootapisessionauthzjava.policy.InvalidPolicyException;
import com.github.lisama569.springbootapisessionauthzjava.policy.PolicyService;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 授权策略运行期热更新测试。
 */
class PolicyHotReloadTest {

    private static final Logger log = LoggerFactory.getLogger(PolicyHotReloadTest.class);

    private static List<PolicyRule> denyAllFor(String caller) {
        return List.of(new PolicyRule(caller, "docs", Action.READ, Effect.DENY));
    }

    @Test
    void invalidAndConflictingRulesAreRejectedWithoutTouchingCurrentPolicy() {
        PolicyService policies = new PolicyService();
        long before = policies.current().version();

        // null 规则集
        assertThatThrownBy(() -> policies.replace(before, null))
                .isInstanceOf(InvalidPolicyException.class);
        // 空字段
        assertThatThrownBy(() -> policies.replace(before,
                List.of(new PolicyRule(" ", "docs", Action.READ, Effect.ALLOW))))
                .isInstanceOf(InvalidPolicyException.class);
        // null 动作/效果
        assertThatThrownBy(() -> policies.replace(before,
                List.of(new PolicyRule("x", "docs", null, Effect.ALLOW))))
                .isInstanceOf(InvalidPolicyException.class);
        assertThatThrownBy(() -> policies.replace(before,
                List.of(new PolicyRule("x", "docs", Action.READ, null))))
                .isInstanceOf(InvalidPolicyException.class);
        // 同一键重复且效果冲突
        List<PolicyRule> duplicates = List.of(
                new PolicyRule("x", "docs", Action.READ, Effect.ALLOW),
                new PolicyRule("x", "docs", Action.READ, Effect.DENY));
        assertThatThrownBy(() -> policies.replace(before, duplicates))
                .isInstanceOf(InvalidPolicyException.class);

        // 所有非法更新都被拒绝：版本仍是 1，初始规则原样生效
        assertThat(policies.current().version()).isEqualTo(1L);
        assertThat(policies.evaluate(policies.current(), "alice", "docs", Action.READ))
                .isEqualTo(Effect.ALLOW);
        log.info("policy-hotreload | policyVersion={} | result=CURRENT_UNCHANGED_AFTER_INVALID_INPUT", before);
    }

    @Test
    void staleVersionIsRejectedAndOnlyOneConcurrentReplaceWins() throws Exception {
        PolicyService policies = new PolicyService();

        // 版本号过期：必须拒绝
        Policy v2 = policies.replace(1L, denyAllFor("alice"));
        assertThat(v2.version()).isEqualTo(2L);
        assertThatThrownBy(() -> policies.replace(1L, denyAllFor("bob")))
                .isInstanceOf(InvalidPolicyException.class)
                .hasMessageContaining("version conflict");
        assertThat(policies.current().version()).isEqualTo(2L);
        log.info("policy-hotreload | policyVersion=2 | result=STALE_VERSION_REJECTED");

        // 并发替换同一版本：恰好一个成功，其余全部冲突失败，生效版本只 +1
        int threads = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CyclicBarrier barrier = new CyclicBarrier(threads);
        try {
            List<Future<Boolean>> futures = new ArrayList<>();
            for (int i = 0; i < threads; i++) {
                final long callerIdx = i;
                futures.add(pool.submit(() -> {
                    barrier.await();
                    try {
                        policies.replace(2L, List.of(
                                new PolicyRule("c" + callerIdx, "docs", Action.READ, Effect.ALLOW)));
                        return true;
                    } catch (InvalidPolicyException e) {
                        return false;
                    }
                }));
            }
            long wins = 0;
            for (Future<Boolean> f : futures) {
                if (f.get()) {
                    wins++;
                }
            }
            assertThat(wins).isEqualTo(1);
            assertThat(policies.current().version()).isEqualTo(3L);
        } finally {
            pool.shutdown();
        }
        log.info("policy-hotreload | policyVersion=3 | result=ONE_OF_16_CONCURRENT_REPLACES_WON");
    }

    @Test
    void oldPolicySnapshotsAreImmutableAndPriorDecisionsAreNotRewritten() {
        PolicyService policies = new PolicyService();
        Policy old = policies.current();
        // 用旧快照完成的判定结果
        Effect decisionUnderV1 = policies.evaluate(old, "alice", "docs", Action.READ);
        assertThat(decisionUnderV1).isEqualTo(Effect.ALLOW);

        policies.replace(1L, List.of(
                new PolicyRule("alice", "docs", Action.READ, Effect.DENY)));

        // 旧快照内容与基于它已完成的判定不被追溯改写
        assertThat(old.version()).isEqualTo(1L);
        assertThat(policies.evaluate(old, "alice", "docs", Action.READ)).isEqualTo(decisionUnderV1);
        // 新策略是完整的另一份快照
        Policy current = policies.current();
        assertThat(current.version()).isEqualTo(2L);
        assertThat(policies.evaluate(current, "alice", "docs", Action.READ)).isEqualTo(Effect.DENY);
        log.info("policy-hotreload | policyVersion=1->2 | action=alice:docs:READ | v1Result=ALLOW | v2Result=DENY | result=SNAPSHOT_STABLE");
    }

    @Test
    void aRequestSeesExactlyOneCompleteVersion() {
        PolicyService policies = new PolicyService();
        // 模拟一次请求：开始时取一次快照，期间发生热更新，本次评估仍使用同一完整快照
        Policy seen = policies.current();
        policies.replace(1L, List.of(new PolicyRule("zoe", "docs", Action.READ, Effect.ALLOW)));
        Effect duringOldRequest = policies.evaluate(seen, "zoe", "docs", Action.READ);
        // 旧版本里没有 zoe 规则 -> 默认拒绝；新版本里才允许。不会出现“半更新”视图
        assertThat(duringOldRequest).isEqualTo(Effect.DENY);
        assertThat(policies.evaluate(policies.current(), "zoe", "docs", Action.READ))
                .isEqualTo(Effect.ALLOW);
        log.info("policy-hotreload | policyVersion=1(during request) | action=zoe:docs:READ | result=DENY_ON_OLD_ALLOW_ON_NEW");
    }
}
