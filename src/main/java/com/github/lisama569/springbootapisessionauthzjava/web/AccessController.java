package com.github.lisama569.springbootapisessionauthzjava.web;

import com.github.lisama569.springbootapisessionauthzjava.authz.AuditLog;
import com.github.lisama569.springbootapisessionauthzjava.authz.Decision;
import com.github.lisama569.springbootapisessionauthzjava.authz.DecisionOutcome;
import com.github.lisama569.springbootapisessionauthzjava.authz.DecisionService;
import com.github.lisama569.springbootapisessionauthzjava.authz.DenialReason;
import com.github.lisama569.springbootapisessionauthzjava.web.ApiDtos.AccessRequest;
import com.github.lisama569.springbootapisessionauthzjava.web.ApiDtos.AccessResponse;
import com.github.lisama569.springbootapisessionauthzjava.web.ApiDtos.ErrorResponse;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 受保护资源访问入口。
 *
 * <p>所有受保护请求都经过同一判定路径：资源/动作作为请求体参数提交，
 * 因此对“资源不存在”和“无权限”返回完全一致的拒绝，不通过响应差异泄露资源是否存在。
 * 失败原因通过 {@code reason} 稳定区分（认证类 401、授权类 403）。
 */
@RestController
@RequestMapping
public class AccessController {

    private final DecisionService decisionService;
    private final AuditLog auditLog;

    public AccessController(DecisionService decisionService, AuditLog auditLog) {
        this.decisionService = decisionService;
        this.auditLog = auditLog;
    }

    /** 对 (resource, action) 发起一次受保护访问判定。 */
    @PostMapping("/api/access")
    public ResponseEntity<?> access(
            @RequestHeader(name = "Authorization", required = false) String authorization,
            @RequestHeader(name = "X-Caller-Hint", required = false) String callerHint,
            @RequestBody AccessRequest request) {
        String token = bearer(authorization);
        Decision decision = decisionService.decide(
                token, callerHint, request.resource(), request.action());

        if (decision.outcome() == DecisionOutcome.ALLOW) {
            return ResponseEntity.ok(new AccessResponse(
                    true,
                    decision.decisionId(),
                    "ALLOW: caller=" + decision.caller()
                            + " resource=" + decision.resource()
                            + " action=" + decision.action()
                            + " policyVersion=" + decision.policyVersion()));
        }
        return denied(decision);
    }

    /** 查询全部判定记录（本地验证/测试观察用）。 */
    @GetMapping("/admin/audit")
    public List<Decision> audit() {
        return auditLog.all();
    }

    private static ResponseEntity<ErrorResponse> denied(Decision decision) {
        DenialReason reason = decision.reason();
        HttpStatus status = (reason == DenialReason.ACCESS_DENIED)
                ? HttpStatus.FORBIDDEN : HttpStatus.UNAUTHORIZED;
        // 对所有拒绝使用同一形态的响应体，仅以稳定 reason 区分，不回显资源细节
        ErrorResponse body = new ErrorResponse(
                "access_denied",
                reason.name(),
                decision.decisionId(),
                messageOf(reason),
                decision.timestamp());
        return ResponseEntity.status(status).body(body);
    }

    private static String messageOf(DenialReason reason) {
        return switch (reason) {
            case MISSING_CREDENTIAL -> "缺少凭证";
            case UNKNOWN_CREDENTIAL -> "凭证无效";
            case CREDENTIAL_EXPIRED -> "凭证已过期";
            case CREDENTIAL_REVOKED -> "凭证已被撤销";
            case ACCESS_DENIED -> "已认证但无权执行该操作";
        };
    }

    /** 解析 Bearer 令牌；非法格式一律视为未携带有效凭证。 */
    private static String bearer(String authorization) {
        if (authorization == null || authorization.isBlank()) {
            return null;
        }
        String prefix = "Bearer ";
        if (!authorization.startsWith(prefix)) {
            return null;
        }
        String token = authorization.substring(prefix.length()).trim();
        return token.isEmpty() ? null : token;
    }
}
