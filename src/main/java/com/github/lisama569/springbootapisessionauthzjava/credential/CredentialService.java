package com.github.lisama569.springbootapisessionauthzjava.credential;

import com.github.lisama569.springbootapisessionauthzjava.time.TimeSource;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Service;

/**
 * 会话凭证的签发、查询、续期与撤销。
 *
 * <p>线程安全保障：所有改变单个凭证的操作（续期/撤销）都在该凭证专属的
 * {@link Entry} 监视器上串行执行，因此多个并发请求同时续期或撤销同一凭证时：
 * <ul>
 *   <li>续期不会重复生效（每次续期版本号 +1，过期时间基于“上次提交”的时钟）；</li>
 *   <li>撤销后到达的续期一律被拒绝，不会越权放行；</li>
 *   <li>不会出现读到半更新状态而把有效凭证误判失效。</li>
 * </ul>
 */
@Service
public class CredentialService {

    /** 允许的 TTL 范围：1 秒 ~ 24 小时。 */
    public static final Duration MIN_TTL = Duration.ofSeconds(1);
    public static final Duration MAX_TTL = Duration.ofHours(24);

    private final TimeSource timeSource;
    private final ConcurrentHashMap<String, Entry> entries = new ConcurrentHashMap<>();

    public CredentialService(TimeSource timeSource) {
        this.timeSource = timeSource;
    }

    /** 为指定调用方签发新凭证。 */
    public Credential issue(String caller, Duration ttl) {
        String normalizedCaller = requireCaller(caller);
        Duration safeTtl = requireTtl(ttl);
        Instant now = timeSource.now();
        Credential credential = new Credential(
                UUID.randomUUID().toString(),
                normalizedCaller,
                now,
                now.plus(safeTtl),
                1L,
                false);
        entries.put(credential.tokenId(), new Entry(credential));
        return credential;
    }

    /**
     * 按当前时钟解释凭证：未知 token 返回 {@link Optional#empty()}。
     * 撤销优先于过期判定；过期边界为 {@code now >= expiresAt}。
     */
    public Optional<CredentialView> inspect(String tokenId) {
        if (tokenId == null || tokenId.isBlank()) {
            return Optional.empty();
        }
        Entry entry = entries.get(tokenId);
        if (entry == null) {
            return Optional.empty();
        }
        Credential snapshot;
        synchronized (entry) {
            snapshot = entry.credential;
        }
        return Optional.of(new CredentialView(snapshot, statusOf(snapshot, timeSource.now())));
    }

    /**
     * 原子续期：仅对“当前时刻仍有效（未撤销、未过期）”的凭证生效。
     * 已撤销或已过期的凭证不能被续期“复活”。
     */
    public Credential renew(String tokenId, Duration ttl) {
        Entry entry = requireEntry(tokenId);
        Duration safeTtl = requireTtl(ttl);
        synchronized (entry) {
            Credential current = entry.credential;
            CredentialStatus status = statusOf(current, timeSource.now());
            if (status == CredentialStatus.REVOKED) {
                throw new CredentialOperationException("凭证已被撤销，不能续期: " + tokenId);
            }
            if (status == CredentialStatus.EXPIRED) {
                throw new CredentialOperationException("凭证已过期，不能续期: " + tokenId);
            }
            Instant now = timeSource.now();
            Credential renewed = new Credential(
                    current.tokenId(),
                    current.caller(),
                    now,
                    now.plus(safeTtl),
                    current.version() + 1L,
                    false);
            entry.credential = renewed;
            return renewed;
        }
    }

    /**
     * 撤销凭证（幂等）。
     *
     * @return 本次调用是否真正把状态从“未撤销”改为“已撤销”；重复撤销返回 {@code false}。
     * @throws CredentialOperationException 未知凭证
     */
    public boolean revoke(String tokenId) {
        Entry entry = requireEntry(tokenId);
        synchronized (entry) {
            Credential current = entry.credential;
            if (current.revoked()) {
                return false;
            }
            entry.credential = new Credential(
                    current.tokenId(),
                    current.caller(),
                    current.issuedAt(),
                    current.expiresAt(),
                    current.version(),
                    true);
            return true;
        }
    }

    private Entry requireEntry(String tokenId) {
        if (tokenId == null || tokenId.isBlank()) {
            throw new CredentialOperationException("缺少凭证标识");
        }
        Entry entry = entries.get(tokenId);
        if (entry == null) {
            throw new CredentialOperationException("未知凭证: " + tokenId);
        }
        return entry;
    }

    private static String requireCaller(String caller) {
        if (caller == null || caller.isBlank()) {
            throw new CredentialOperationException("调用方不能为空");
        }
        return caller.trim();
    }

    private static Duration requireTtl(Duration ttl) {
        if (ttl == null) {
            throw new CredentialOperationException("ttl 不能为空");
        }
        if (ttl.compareTo(MIN_TTL) < 0 || ttl.compareTo(MAX_TTL) > 0) {
            throw new CredentialOperationException(
                    "ttl 超出允许范围 [" + MIN_TTL.getSeconds() + "s, " + MAX_TTL.toSeconds() + "s]: "
                            + ttl.getSeconds() + "s");
        }
        return ttl;
    }

    private static CredentialStatus statusOf(Credential credential, Instant now) {
        if (credential.revoked()) {
            return CredentialStatus.REVOKED;
        }
        // 边界定义：now == expiresAt 即过期，保证过期前后可复现
        if (!now.isBefore(credential.expiresAt())) {
            return CredentialStatus.EXPIRED;
        }
        return CredentialStatus.VALID;
    }

    /** 可变持有者，以自身作为单凭证粒度的锁。 */
    private static final class Entry {
        private Credential credential;

        private Entry(Credential credential) {
            this.credential = credential;
        }
    }

    /** 查询时刻的凭证视图。 */
    public record CredentialView(Credential credential, CredentialStatus status) {
    }
}
