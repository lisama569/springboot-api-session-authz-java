package com.github.lisama569.springbootapisessionauthzjava.authz;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lisama569.springbootapisessionauthzjava.domain.Action;
import com.github.lisama569.springbootapisessionauthzjava.domain.AuthzDecision;
import com.github.lisama569.springbootapisessionauthzjava.domain.DenyReason;
import com.github.lisama569.springbootapisessionauthzjava.web.ErrorResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

/**
 * 鉴权拦截器：保护资源接口。
 *
 * <p>不泄露资源存在性的设计：无论资源是否存在，未携带凭证 / 凭证过期 / 凭证被撤销 /
 * 已认证但无权限，HTTP 状态码统一为 404，且响应体结构完全一致。调用方通过响应体中的
 * {@code error} 原因码区分失败类型，而资源的有无无法从任何响应差异中推断。
 */
@Component
public class AuthInterceptor implements HandlerInterceptor {

    private static final Logger log = LoggerFactory.getLogger(AuthInterceptor.class);

    public static final String CALLER_ATTRIBUTE = "authz.caller";
    public static final String DECISION_ATTRIBUTE = "authz.decision";

    private static final String BEARER_PREFIX = "Bearer ";

    /** 所有鉴权拒绝统一使用的不透明状态码与消息。 */
    private static final HttpStatus DENY_STATUS = HttpStatus.NOT_FOUND;
    private static final String DENY_MESSAGE = "resource not found";

    /** 各拒绝原因对应的稳定机器可读错误码。 */
    private static final Map<DenyReason, String> ERROR_CODES = Map.of(
            DenyReason.NO_CREDENTIAL, "NO_CREDENTIAL",
            DenyReason.INVALID_CREDENTIAL, "INVALID_CREDENTIAL",
            DenyReason.CREDENTIAL_EXPIRED, "CREDENTIAL_EXPIRED",
            DenyReason.CREDENTIAL_REVOKED, "CREDENTIAL_REVOKED",
            DenyReason.ACCESS_DENIED, "ACCESS_DENIED"
    );

    private final AuthorizationService authorization;
    private final ObjectMapper objectMapper;

    public AuthInterceptor(AuthorizationService authorization, ObjectMapper objectMapper) {
        this.authorization = authorization;
        this.objectMapper = objectMapper;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws Exception {
        String token = extractToken(request);
        String resource = extractResource(request);
        Action action = mapAction(request.getMethod());

        AuthzDecision decision = authorization.decide(token, resource, action);
        request.setAttribute(DECISION_ATTRIBUTE, decision);
        if (decision.allowed()) {
            request.setAttribute(CALLER_ATTRIBUTE, decision.caller());
            return true;
        }
        writeDeny(response, decision);
        return false;
    }

    /** 从 Authorization 头提取 Bearer 令牌；缺失或方案非 Bearer 时返回 null（视为无凭证）。 */
    private static String extractToken(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        if (header != null && header.startsWith(BEARER_PREFIX)) {
            String token = header.substring(BEARER_PREFIX.length()).trim();
            return token.isEmpty() ? null : token;
        }
        return null;
    }

    /** 从 /api/resources/{type}/{id} 中提取资源类型 {type} 作为授权资源。 */
    private static String extractResource(HttpServletRequest request) {
        String uri = request.getRequestURI();
        String prefix = "/api/resources/";
        int start = uri.indexOf(prefix);
        if (start < 0) {
            return "";
        }
        String rest = uri.substring(start + prefix.length());
        int slash = rest.indexOf('/');
        return slash < 0 ? rest : rest.substring(0, slash);
    }

    /** HTTP 方法到资源动作的映射；未知方法按最小权限原则映射为 DELETE（默认拒绝路径）。 */
    static Action mapAction(String httpMethod) {
        if (httpMethod == null) {
            return Action.DELETE;
        }
        return switch (httpMethod.toUpperCase()) {
            case "GET", "HEAD" -> Action.READ;
            case "POST", "PUT", "PATCH" -> Action.WRITE;
            default -> Action.DELETE;
        };
    }

    private void writeDeny(HttpServletResponse response, AuthzDecision decision) throws Exception {
        String code = ERROR_CODES.get(decision.denyReason());
        response.setStatus(DENY_STATUS.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        objectMapper.writeValue(response.getWriter(), new ErrorResponse(code, DENY_MESSAGE));
        log.info("request denied | httpStatus={} | errorCode={}", DENY_STATUS.value(), code);
    }
}
