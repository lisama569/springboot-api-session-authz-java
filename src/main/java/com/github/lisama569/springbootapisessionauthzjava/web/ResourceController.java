package com.github.lisama569.springbootapisessionauthzjava.web;

import com.github.lisama569.springbootapisessionauthzjava.authz.AuthInterceptor;
import com.github.lisama569.springbootapisessionauthzjava.domain.AuthzDecision;
import jakarta.servlet.http.HttpServletRequest;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 受保护的示例资源接口：/api/resources/{type}/{id}
 *
 * <p>所有请求都先经过 {@code AuthInterceptor}：只有判定放行后才会进入本控制器，
 * 因此“无权限”与“资源不存在”对外呈现完全一致，响应差异无法反推资源是否存在。
 */
@RestController
@RequestMapping("/api/resources")
public class ResourceController {

    @GetMapping("/{type}/{id}")
    public ResponseEntity<Map<String, Object>> read(@PathVariable String type, @PathVariable String id,
                                                    HttpServletRequest request) {
        return ResponseEntity.ok(body(type, id, "READ", request));
    }

    @PostMapping("/{type}/{id}")
    public ResponseEntity<Map<String, Object>> create(@PathVariable String type, @PathVariable String id,
                                                      HttpServletRequest request) {
        return ResponseEntity.ok(body(type, id, "WRITE", request));
    }

    @PutMapping("/{type}/{id}")
    public ResponseEntity<Map<String, Object>> write(@PathVariable String type, @PathVariable String id,
                                                     HttpServletRequest request) {
        return ResponseEntity.ok(body(type, id, "WRITE", request));
    }

    @DeleteMapping("/{type}/{id}")
    public ResponseEntity<Map<String, Object>> delete(@PathVariable String type, @PathVariable String id,
                                                      HttpServletRequest request) {
        return ResponseEntity.ok(body(type, id, "DELETE", request));
    }

    private static Map<String, Object> body(String type, String id, String action, HttpServletRequest request) {
        AuthzDecision decision = (AuthzDecision) request.getAttribute(AuthInterceptor.DECISION_ATTRIBUTE);
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("resource", type + "/" + id);
        map.put("action", action);
        map.put("caller", request.getAttribute(AuthInterceptor.CALLER_ATTRIBUTE));
        map.put("policyVersion", decision == null ? null : decision.policyVersion());
        map.put("content", "protected content of " + type + "/" + id);
        return map;
    }
}
