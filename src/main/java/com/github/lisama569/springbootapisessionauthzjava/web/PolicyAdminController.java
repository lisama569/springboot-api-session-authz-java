package com.github.lisama569.springbootapisessionauthzjava.web;

import com.github.lisama569.springbootapisessionauthzjava.policy.Policy;
import com.github.lisama569.springbootapisessionauthzjava.policy.PolicyRule;
import com.github.lisama569.springbootapisessionauthzjava.policy.PolicyService;
import com.github.lisama569.springbootapisessionauthzjava.web.ApiDtos.PolicyReplaceRequest;
import com.github.lisama569.springbootapisessionauthzjava.web.ApiDtos.PolicyResponse;
import com.github.lisama569.springbootapisessionauthzjava.web.ApiDtos.RuleDto;
import java.util.List;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** 策略查询与热更新端点（本地演示，无额外管理鉴权）。 */
@RestController
@RequestMapping("/admin/policy")
public class PolicyAdminController {

    private final PolicyService policyService;

    public PolicyAdminController(PolicyService policyService) {
        this.policyService = policyService;
    }

    /** 查询当前生效策略版本与完整规则。 */
    @GetMapping
    public PolicyResponse current() {
        return toResponse(policyService.current());
    }

    /**
     * 原子替换整套策略。非法/冲突/版本不匹配会被拒绝（409 或 400），当前策略保持不变。
     */
    @PutMapping
    public PolicyResponse replace(@RequestBody PolicyReplaceRequest request) {
        List<PolicyRule> rules = request.rules() == null ? List.of() : request.rules().stream()
                .map(r -> new PolicyRule(r.caller(), r.resource(), r.action()))
                .toList();
        return toResponse(policyService.replace(rules, request.expectedVersion()));
    }

    private static PolicyResponse toResponse(Policy policy) {
        List<RuleDto> rules = policy.rules().stream()
                .map(r -> new RuleDto(r.caller(), r.resource(), r.action()))
                .toList();
        return new PolicyResponse(policy.version(), rules);
    }
}
