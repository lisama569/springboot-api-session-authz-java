package com.github.lisama569.springbootapisessionauthzjava.tests;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.github.lisama569.springbootapisessionauthzjava.policy.InvalidPolicyException;
import com.github.lisama569.springbootapisessionauthzjava.policy.Policy;
import com.github.lisama569.springbootapisessionauthzjava.policy.PolicyRule;
import com.github.lisama569.springbootapisessionauthzjava.policy.PolicyService;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;

/** 策略热更新：原子可见、非法/冲突不影响当前策略、版本单调。 */
class PolicyHotReloadTests {

    private final PolicyService policies = new PolicyService();

    private static final List<PolicyRule> PLAN_A =
            List.of(new PolicyRule("alice", "docs", "read"));
    private static final List<PolicyRule> PLAN_B = List.of(
            new PolicyRule("alice", "docs", "read"),
            new PolicyRule("bob", "docs", "write"));

    @Test
    void replacePublishesImmutableSnapshotAndIncrementsVersion() {
        Policy before = policies.current();
        Policy after = policies.replace(PLAN_A, null);

        assertThat(after.version()).isEqualTo(before.version() + 1);
        assertThat(after.rules()).hasSize(1);
        // 已发出的旧快照内容不被修改
        assertThat(before.rules()).hasSize(3);
        assertThat(policies.current()).isSameAs(after);

        // 不可变性：尝试修改快照规则列表应失败
        assertThatThrownBy(() -> after.rules().add(new PolicyRule("x", "y", "z")))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void invalidOrConflictingPolicyIsRejectedWithoutTouchingActivePolicy() {
        Policy active = policies.current();

        // 空字段
        assertThatThrownBy(() -> policies.replace(
                List.of(new PolicyRule(" ", "docs", "read")), null))
                .isInstanceOf(InvalidPolicyException.class);
        // 重复三元组（冲突）
        assertThatThrownBy(() -> policies.replace(
                List.of(
                        new PolicyRule("alice", "docs", "read"),
                        new PolicyRule("alice", "docs", "read")), null))
                .isInstanceOf(InvalidPolicyException.class);
        // null 列表
        assertThatThrownBy(() -> policies.replace(null, null))
                .isInstanceOf(InvalidPolicyException.class);

        // 当前生效策略原样不变
        assertThat(policies.current()).isSameAs(active);
        assertThat(policies.current().version()).isEqualTo(active.version());
    }

    @Test
    void optimisticVersionConflictIsRejected() {
        Policy active = policies.current();
        policies.replace(PLAN_A, active.version());

        // 拿着旧版本号更新应被拒绝
        assertThatThrownBy(() -> policies.replace(PLAN_B, active.version()))
                .isInstanceOf(InvalidPolicyException.class)
                .hasMessageContaining("版本冲突");
        // 拒绝后当前策略不变
        assertThat(policies.current().rules()).hasSize(1);
    }

    @Test
    void concurrentReadersOnlyEverObserveOneCompletePolicy() throws Exception {
        // 先把策略基线切到 PLAN_A，使后续所有被观察版本都只可能是 PLAN_A / PLAN_B
        policies.replace(PLAN_A, null);

        int readers = 16;
        int iterations = 200;
        ExecutorService pool = Executors.newFixedThreadPool(readers + 1);
        CountDownLatch start = new CountDownLatch(1);
        // 每个版本第一次观察到的规则内容；所有线程对同一版本的观察必须完全一致 => 无撕裂读
        ConcurrentHashMap<Long, List<PolicyRule>> observedByVersion = new ConcurrentHashMap<>();
        List<Future<?>> futures = new ArrayList<>();

        for (int r = 0; r < readers; r++) {
            futures.add(pool.submit(() -> {
                start.await();
                for (int i = 0; i < iterations; i++) {
                    Policy snapshot = policies.current();
                    List<PolicyRule> rules = snapshot.rules();
                    // 快照内容必须是两套完整策略之一，绝不允许混合/半成品
                    assertThat(rules.equals(PLAN_A) || rules.equals(PLAN_B))
                            .as("观察到非完整策略: %s", rules).isTrue();
                    observedByVersion.computeIfAbsent(snapshot.version(), k -> List.copyOf(rules));
                    synchronized (observedByVersion) {
                        assertThat(observedByVersion.get(snapshot.version())).isEqualTo(rules);
                    }
                }
                return null;
            }));
        }
        futures.add(pool.submit(() -> {
            start.await();
            for (int i = 0; i < iterations; i++) {
                policies.replace(i % 2 == 0 ? PLAN_A : PLAN_B, null);
            }
            return null;
        }));

        start.countDown();
        for (Future<?> f : futures) {
            f.get(30, TimeUnit.SECONDS);
        }
        pool.shutdown();

        // 写后最终版本应远超基线版本，证明发生过多次原子发布
        long finalVersion = policies.current().version();
        assertThat(finalVersion).isGreaterThan(2L);

        // 每个版本对应唯一一套完整规则，且所有读者观察一致（上面 computeIfAbsent 后比对）
        observedByVersion.forEach((version, rules) -> {
            if (rules.size() == 1) {
                assertThat(rules).isEqualTo(PLAN_A);
            } else {
                assertThat(rules).isEqualTo(PLAN_B);
            }
        });
    }
}
