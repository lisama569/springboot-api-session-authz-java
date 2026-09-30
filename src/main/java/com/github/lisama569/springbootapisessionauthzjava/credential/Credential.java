package com.github.lisama569.springbootapisessionauthzjava.credential;

import java.time.Instant;

/**
 * 不可变会话凭证视图。
 *
 * @param tokenId 凭证标识
 * @param caller 凭证所属调用方
 * @param issuedAt 签发时间
 * @param expiresAt 过期时间（边界：expiresAt 时刻即为过期）
 * @param version 凭证版本，每次续期递增
 * @param revoked 是否被撤销
 */
public record Credential(
        String tokenId,
        String caller,
        Instant issuedAt,
        Instant expiresAt,
        long version,
        boolean revoked) {
}
