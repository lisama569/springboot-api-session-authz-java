package com.github.lisama569.springbootapisessionauthzjava.web;

import com.github.lisama569.springbootapisessionauthzjava.domain.SessionInfo;
import com.github.lisama569.springbootapisessionauthzjava.session.SessionService;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 会话凭证管理接口（本地开发用，不接外部身份服务）：签发 / 查询 / 续期 / 撤销。
 */
@RestController
@RequestMapping("/api/sessions")
public class SessionController {

    private final SessionService sessions;

    public SessionController(SessionService sessions) {
        this.sessions = sessions;
    }

    public record IssueRequest(String caller, Long ttlSeconds) {}

    /** 为指定调用方签发凭证。 */
    @PostMapping
    public ResponseEntity<Map<String, Object>> issue(@RequestBody IssueRequest body) {
        if (body == null || body.caller() == null || body.caller().isBlank()) {
            throw new IllegalArgumentException("caller must not be blank");
        }
        Duration ttl = body.ttlSeconds() == null ? null : Duration.ofSeconds(body.ttlSeconds());
        SessionInfo info = sessions.issue(body.caller(), ttl);
        return ResponseEntity.status(HttpStatus.CREATED).body(render(info));
    }

    /** 查询凭证当前状态；不存在返回 404，且不泄露任何其他信息。 */
    @GetMapping("/{token}")
    public ResponseEntity<Map<String, Object>> inspect(@PathVariable String token) {
        SessionInfo info = sessions.lookup(token);
        if (info == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Map.of("error", "NOT_FOUND", "message", "session not found"));
        }
        return ResponseEntity.ok(render(info));
    }

    public record RenewRequest(Long ttlSeconds) {}

    /**
     * 续期凭证。结果语义：
     * RENEWED=200；EXPIRED/REVOKED=409（凭证不能复活）；UNKNOWN=404。
     */
    @PostMapping("/{token}/renew")
    public ResponseEntity<Map<String, Object>> renew(@PathVariable String token,
                                                     @RequestBody(required = false) RenewRequest body) {
        Duration ttl = (body == null || body.ttlSeconds() == null)
                ? null : Duration.ofSeconds(body.ttlSeconds());
        SessionService.RenewOutcome outcome = sessions.renew(token, ttl);
        return switch (outcome.result()) {
            case RENEWED -> ResponseEntity.ok(withResult(outcome.info(), "RENEWED"));
            case EXPIRED -> ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(withResult(outcome.info(), "CREDENTIAL_EXPIRED"));
            case REVOKED -> ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(withResult(outcome.info(), "CREDENTIAL_REVOKED"));
            case UNKNOWN -> ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Map.of("error", "NOT_FOUND", "message", "session not found"));
        };
    }

    /**
     * 撤销凭证。REVOKED=首次撤销成功；ALREADY_REVOKED=幂等的重复撤销；UNKNOWN=404。
     */
    @DeleteMapping("/{token}")
    public ResponseEntity<Map<String, Object>> revoke(@PathVariable String token) {
        SessionService.RevokeOutcome outcome = sessions.revoke(token);
        return switch (outcome.result()) {
            case REVOKED -> ResponseEntity.ok(withResult(outcome.info(), "REVOKED"));
            case ALREADY_REVOKED -> ResponseEntity.ok(withResult(outcome.info(), "ALREADY_REVOKED"));
            case UNKNOWN -> ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Map.of("error", "NOT_FOUND", "message", "session not found"));
        };
    }

    static Map<String, Object> render(SessionInfo info) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("token", info.token());
        map.put("caller", info.caller());
        map.put("issuedAt", info.issuedAt().toString());
        map.put("expiresAt", info.expiresAt().toString());
        map.put("revoked", info.revoked());
        map.put("revokedAt", info.revokedAt() == null ? null : info.revokedAt().toString());
        map.put("renewedTimes", info.renewedTimes());
        return map;
    }

    private static Map<String, Object> withResult(SessionInfo info, String result) {
        Map<String, Object> map = render(info);
        map.put("result", result);
        return map;
    }
}
