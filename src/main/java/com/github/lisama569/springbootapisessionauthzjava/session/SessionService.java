package com.github.lisama569.springbootapisessionauthzjava.session;

import com.github.lisama569.springbootapisessionauthzjava.clock.AuthClock;
import com.github.lisama569.springbootapisessionauthzjava.domain.CredentialStatus;
import com.github.lisama569.springbootapisessionauthzjava.domain.SessionInfo;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * 会话凭证服务：负责凭证签发、无锁快照式查找、原子续期与撤销。
 *
 * <p>并发保障：每个令牌对应一个不可变 {@link Entry}，所有变更都通过
 * {@link ConcurrentHashMap#replace} 的 CAS 语义完成。因此：
 * <ul>
 *   <li>并发撤销：只有第一个 CAS 成功返回 REVOKED，其余返回 ALREADY_REVOKED，不会重复生效；</li>
 *   <li>并发续期：每次续期基于最新快照原子地延长到期时间，不会丢失续期、不会出现半生效状态；</li>
 *   <li>续期与撤销竞争：撤销一旦 CAS 成功，后续续期一律 REVOKED，绝不越权放行。</li>
 * </ul>
 */
@Service
public class SessionService {

    /** 撤销操作的结果。 */
    public enum RevokeResult { REVOKED, ALREADY_REVOKED, UNKNOWN }

    /** 续期操作的结果。 */
    public enum RenewResult { RENEWED, EXPIRED, REVOKED, UNKNOWN }

    /** 凭证不可变状态快照。 */
    private record Entry(String token, String caller, Instant issuedAt, Instant expiresAt,
                        boolean revoked, Instant revokedAt, int renewedTimes) {
    }

    /** 单次续期允许的最大 TTL：24 小时。 */
    static final long MAX_TTL_SECONDS = 24L * 60 * 60;

    private final AuthClock clock;
    private final long defaultTtlSeconds;
    private final ConcurrentHashMap<String, Entry> sessions = new ConcurrentHashMap<>();
    private final SecureRandom random = new SecureRandom();

    public SessionService(AuthClock clock,
                          @Value("${authz.session.ttl-seconds:300}") long defaultTtlSeconds) {
        this.clock = clock;
        this.defaultTtlSeconds = defaultTtlSeconds;
    }

    /**
     * 为调用方签发新凭证。
     *
     * @param caller 调用方标识，不能为空
     * @param ttl    存活时长，null 表示使用默认值；必须为正且不超过 {@link #MAX_TTL_SECONDS}
     */
    public SessionInfo issue(String caller, Duration ttl) {
        if (caller == null || caller.isBlank()) {
            throw new IllegalArgumentException("caller must not be blank");
        }
        Duration lifetime = resolveTtl(ttl);
        Instant now = clock.now();
        while (true) {
            String token = newToken();
            Entry entry = new Entry(token, caller, now, now.plus(lifetime), false, null, 0);
            if (sessions.putIfAbsent(token, entry) == null) {
                return toInfo(entry);
            }
            // 极小概率的令牌碰撞：重新生成重试
        }
    }

    /**
     * 以不可变快照形式返回凭证信息；不存在返回 null。不会因查询而改变任何状态。
     */
    public SessionInfo lookup(String token) {
        if (token == null || token.isBlank()) {
            return null;
        }
        Entry entry = sessions.get(token);
        return entry == null ? null : toInfo(entry);
    }

    /**
     * 判定凭证在当前时刻的状态。时间边界：到期时刻（now == expiresAt）即视为过期。
     */
    public CredentialStatus statusOf(String token) {
        if (token == null || token.isBlank()) {
            return CredentialStatus.ABSENT;
        }
        Entry entry = sessions.get(token);
        if (entry == null) {
            return CredentialStatus.UNKNOWN;
        }
        if (entry.revoked()) {
            return CredentialStatus.REVOKED;
        }
        if (!clock.now().isBefore(entry.expiresAt())) {
            return CredentialStatus.EXPIRED;
        }
        return CredentialStatus.VALID;
    }

    /** 续期结果：结果码 + 续期后的最新快照（UNKNOWN 时为 null）。 */
    public record RenewOutcome(RenewResult result, SessionInfo info) {}

    /**
     * 原子续期：基于当前快照 CAS 更新到期时间与续期计数。
     * 已过期或已撤销的凭证不能通过续期复活。
     */
    public RenewOutcome renew(String token, Duration ttl) {
        if (token == null || token.isBlank()) {
            return new RenewOutcome(RenewResult.UNKNOWN, null);
        }
        Duration lifetime = resolveTtl(ttl);
        while (true) {
            Entry entry = sessions.get(token);
            if (entry == null) {
                return new RenewOutcome(RenewResult.UNKNOWN, null);
            }
            if (entry.revoked()) {
                return new RenewOutcome(RenewResult.REVOKED, toInfo(entry));
            }
            Instant now = clock.now();
            if (!now.isBefore(entry.expiresAt())) {
                return new RenewOutcome(RenewResult.EXPIRED, toInfo(entry));
            }
            Entry renewed = new Entry(entry.token(), entry.caller(), entry.issuedAt(),
                    now.plus(lifetime), false, null, entry.renewedTimes() + 1);
            if (sessions.replace(token, entry, renewed)) {
                return new RenewOutcome(RenewResult.RENEWED, toInfo(renewed));
            }
            // CAS 失败说明有并发变更，基于最新快照重试
        }
    }

    /** 撤销结果：结果码 + 撤销时的快照（UNKNOWN 时为 null）。 */
    public record RevokeOutcome(RevokeResult result, SessionInfo info) {}

    /**
     * 原子撤销：只有第一个成功的 CAS 返回 REVOKED；重复撤销返回 ALREADY_REVOKED。
     * 过期凭证同样可以被撤销（语义上仍是“该令牌作废”），但重复撤销不会重复生效。
     */
    public RevokeOutcome revoke(String token) {
        if (token == null || token.isBlank()) {
            return new RevokeOutcome(RevokeResult.UNKNOWN, null);
        }
        while (true) {
            Entry entry = sessions.get(token);
            if (entry == null) {
                return new RevokeOutcome(RevokeResult.UNKNOWN, null);
            }
            if (entry.revoked()) {
                return new RevokeOutcome(RevokeResult.ALREADY_REVOKED, toInfo(entry));
            }
            Entry revoked = new Entry(entry.token(), entry.caller(), entry.issuedAt(),
                    entry.expiresAt(), true, clock.now(), entry.renewedTimes());
            if (sessions.replace(token, entry, revoked)) {
                return new RevokeOutcome(RevokeResult.REVOKED, toInfo(revoked));
            }
            // CAS 失败说明并发撤销先成功或发生续期，基于最新快照重试
        }
    }

    private Duration resolveTtl(Duration requested) {
        Duration ttl = requested != null ? requested : Duration.ofSeconds(defaultTtlSeconds);
        if (ttl.isZero() || ttl.isNegative()) {
            throw new IllegalArgumentException("ttl must be positive");
        }
        if (ttl.getSeconds() > MAX_TTL_SECONDS) {
            throw new IllegalArgumentException("ttl must not exceed " + MAX_TTL_SECONDS + " seconds");
        }
        return ttl;
    }

    private String newToken() {
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return HexFormat.of().formatHex(bytes);
    }

    /** 清空全部凭证（仅供测试隔离使用）。 */
    public void resetForTesting() {
        sessions.clear();
    }

    private static SessionInfo toInfo(Entry e) {
        return new SessionInfo(e.token(), e.caller(), e.issuedAt(), e.expiresAt(),
                e.revoked(), e.revokedAt(), e.renewedTimes());
    }
}
