package com.github.lisama569.springbootapisessionauthzjava.web;

import com.github.lisama569.springbootapisessionauthzjava.domain.Policy;
import com.github.lisama569.springbootapisessionauthzjava.domain.PolicyRule;
import com.github.lisama569.springbootapisessionauthzjava.policy.PolicyService;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 授权策略热更新管理接口（本地开发用）。
 * 替换采用完整规则集 + 乐观版本号：只有携带当前版本号的更新才会生效。
 */
@RestController
@RequestMapping("/api/policies/current")
public class PolicyAdminController {

    private final PolicyService policies;

    public PolicyAdminController(PolicyService policies) {
        this.policies = policies;
    }

    public record ReplaceRequest(long expectedVersion, List<PolicyRule> rules) {}

    /** 读取当前生效策略快照。 */
    @GetMapping
    public Policy get() {
        return policies.current();
    }

    /** 整体替换策略；版本冲突或规则非法时由全局异常处理映射为 409，旧策略继续生效。 */
    @PutMapping
    public ResponseEntity<Map<String, Object>> replace(@RequestBody ReplaceRequest body) {
        if (body == null) {
            throw new IllegalArgumentException("request body required");
        }
        Policy updated = policies.replace(body.expectedVersion(), body.rules());
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("version", updated.version());
        result.put("rules", updated.rules());
        return ResponseEntity.ok(result);
    }
}
