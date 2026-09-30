package com.github.lisama569.springbootapisessionauthzjava.tests;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lisama569.springbootapisessionauthzjava.policy.PolicyService;
import com.github.lisama569.springbootapisessionauthzjava.session.SessionService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import java.util.List;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

/**
 * 端到端 HTTP 语义测试。
 */
@SpringBootTest
@AutoConfigureMockMvc
class WebApiIntegrationTest {

    private static final Logger log = LoggerFactory.getLogger(WebApiIntegrationTest.class);

    @Autowired
    private MockMvc mvc;
    @Autowired
    private ObjectMapper json;
    @Autowired
    private SessionService sessions;
    @Autowired
    private PolicyService policies;

    @AfterEach
    void resetState() {
        sessions.resetForTesting();
        policies.resetForTesting();
    }

    private String issue(String caller, long ttlSeconds) throws Exception {
        MvcResult result = mvc.perform(post("/api/sessions")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"caller\":\"" + caller + "\",\"ttlSeconds\":" + ttlSeconds + "}"))
                .andExpect(status().isCreated())
                .andReturn();
        return json.readTree(result.getResponse().getContentAsString()).get("token").asText();
    }

    private JsonNode readJson(MvcResult result) throws Exception {
        return json.readTree(result.getResponse().getContentAsString());
    }

    @Test
    void allDenyPathsReturnIdentical404ShapeButDistinctErrorCodes() throws Exception {
        String alice = issue("alice", 300);
        String bob = issue("bob", 300);

        // 1) 未携带凭证
        MvcResult noCred = mvc.perform(get("/api/resources/docs/123"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("NO_CREDENTIAL"))
                .andReturn();

        // 2) 无法识别的凭证
        MvcResult invalid = mvc.perform(get("/api/resources/docs/123")
                        .header("Authorization", "Bearer deadbeefdeadbeef"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("INVALID_CREDENTIAL"))
                .andReturn();

        // 3) 已认证无权限（bob 不能写 docs）
        MvcResult denied = mvc.perform(put("/api/resources/docs/123")
                        .header("Authorization", "Bearer " + bob)
                        .contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("ACCESS_DENIED"))
                .andReturn();

        // 无权限访问不存在资源：响应必须与上面逐字节同构，无法据此判断资源是否存在
        MvcResult deniedMissing = mvc.perform(put("/api/resources/docs/does-not-exist")
                        .header("Authorization", "Bearer " + bob)
                        .contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isNotFound())
                .andReturn();
        org.assertj.core.api.Assertions.assertThat(deniedMissing.getResponse().getContentAsString())
                .isEqualTo(denied.getResponse().getContentAsString());

        // 4) 已撤销
        mvc.perform(delete("/api/sessions/" + bob)).andExpect(status().isOk());
        mvc.perform(get("/api/resources/docs/123").header("Authorization", "Bearer " + bob))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("CREDENTIAL_REVOKED"));

        // 5) 已过期（签发 1 秒，等待到期边界）
        String shortLived = issue("carol", 1);
        Thread.sleep(1100);
        mvc.perform(get("/api/resources/docs/123").header("Authorization", "Bearer " + shortLived))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("CREDENTIAL_EXPIRED"));

        // 放行：alice 可以读 docs，200 且返回受保护内容
        mvc.perform(get("/api/resources/docs/123").header("Authorization", "Bearer " + alice))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.caller").value("alice"))
                .andExpect(jsonPath("$.policyVersion").value(org.hamcrest.Matchers.greaterThanOrEqualTo(1)));

        for (MvcResult r : List.of(noCred, invalid, denied)) {
            JsonNode body = readJson(r);
            log.info("http-deny | httpStatus=404 | errorCode={} | message={}",
                    body.get("error").asText(), body.get("message").asText());
        }
    }

    @Test
    void renewRevokeAndHotReloadWorkOverHttp() throws Exception {
        String bob = issue("bob", 300);

        // 初始策略下 bob 不能写 docs
        mvc.perform(put("/api/resources/docs/1").header("Authorization", "Bearer " + bob)
                        .contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("ACCESS_DENIED"));

        // 热更新到版本 2：授予 bob 对 docs 的 WRITE（完整规则集替换）
        String newRules = """
                {"expectedVersion":1,"rules":[
                  {"caller":"bob","resource":"docs","action":"WRITE","effect":"ALLOW"}
                ]}
                """;
        mvc.perform(put("/api/policies/current")
                        .contentType(MediaType.APPLICATION_JSON).content(newRules))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.version").value(2));

        // 新策略对后续请求立即生效；该策略下只有 bob:docs:WRITE 一条允许规则
        mvc.perform(put("/api/resources/docs/1").header("Authorization", "Bearer " + bob)
                        .contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.policyVersion").value(2));
        // 旧规则被整体替换：bob 对 docs 的 READ 不再存在
        mvc.perform(get("/api/resources/docs/1").header("Authorization", "Bearer " + bob))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("ACCESS_DENIED"));

        // 非法更新（空 caller）必须 409 且当前版本仍是 2
        String invalidRules = """
                {"expectedVersion":2,"rules":[
                  {"caller":" ","resource":"docs","action":"READ","effect":"ALLOW"}
                ]}
                """;
        mvc.perform(put("/api/policies/current")
                        .contentType(MediaType.APPLICATION_JSON).content(invalidRules))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error").value("INVALID_POLICY"));
        mvc.perform(get("/api/policies/current"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.version").value(2));

        // 续期接口：成功后 renewedTimes 增加
        mvc.perform(post("/api/sessions/" + bob + "/renew")
                        .contentType(MediaType.APPLICATION_JSON).content("{\"ttlSeconds\":600}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.result").value("RENEWED"))
                .andExpect(jsonPath("$.renewedTimes").value(1));

        // 撤销：第一次 REVOKED，第二次幂等 ALREADY_REVOKED；撤销后资源访问被拒
        mvc.perform(delete("/api/sessions/" + bob))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.result").value("REVOKED"));
        mvc.perform(delete("/api/sessions/" + bob))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.result").value("ALREADY_REVOKED"));
        mvc.perform(put("/api/resources/docs/1").header("Authorization", "Bearer " + bob)
                        .contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("CREDENTIAL_REVOKED"));
        log.info("http-flow | caller=bob | action=docs:WRITE | policyVersion=2 | result=REVOKED_AFTER_HOTRELOAD");
    }
}
