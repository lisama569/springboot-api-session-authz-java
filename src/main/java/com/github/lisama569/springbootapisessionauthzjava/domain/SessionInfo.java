package com.github.lisama569.springbootapisessionauthzjava.domain;

import java.time.Instant;

/**
 * 凭证在某一时刻的不可变视图，供鉴权与查询使用。
 *
 * @param token      凭证令牌
 * @param caller     调用方标识
 * @param issuedAt   签发时间
 * @param expiresAt  到期时间（边界：expiresAt 时刻即视为过期）
 * @param revoked    是否已撤销
 * @param revokedAt  撤销时间（未撤销为 null）
 * @param renewedTimes 累计成功续期次数
 */
public record SessionInfo(String token, String caller, Instant issuedAt, Instant expiresAt,
                          boolean revoked, Instant revokedAt, int renewedTimes) {
}
