package com.github.lisama569.springbootapisessionauthzjava.web;

import java.time.Instant;
import java.util.List;

/** Web 层请求/响应数据结构（全部不可变）。 */
public final class ApiDtos {

    private ApiDtos() {
    }

    public record IssueRequest(String caller, Long ttlSeconds) {
    }

    public record RenewRequest(Long ttlSeconds) {
    }

    public record SessionResponse(
            String tokenId,
            String caller,
            Instant issuedAt,
            Instant expiresAt,
            long version,
            boolean revoked,
            boolean changed) {
    }

    public record RuleDto(String caller, String resource, String action) {
    }

    public record PolicyReplaceRequest(List<RuleDto> rules, Long expectedVersion) {
    }

    public record PolicyResponse(long version, List<RuleDto> rules) {
    }

    public record AccessRequest(String resource, String action) {
    }

    public record AccessResponse(boolean allowed, String decisionId, String message) {
    }

    /** 统一错误体：不区分资源是否存在，避免侧信道泄露。 */
    public record ErrorResponse(
            String error,
            String reason,
            String decisionId,
            String message,
            Instant timestamp) {
    }
}
