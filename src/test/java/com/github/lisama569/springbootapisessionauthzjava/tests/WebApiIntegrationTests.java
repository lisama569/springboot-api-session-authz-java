package com.github.lisama569.springbootapisessionauthzjava.tests;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.github.lisama569.springbootapisessionauthzjava.authz.AuditLog;
import com.github.lisama569.springbootapisessionauthzjava.support.MutableTimeSource;
import com.github.lisama569.springbootapisessionauthzjava.support.TestConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

/** HTTP 端到端语义。 */
@SpringBootTest
@AutoConfigureMockMvc
@Import(TestConfig.class)
class WebApiIntegrationTests {

    @Autowired
    private MockMvc mvc;
    @Autowired
    private MutableTimeSource clock;
    @Autowired
    private AuditLog auditLog;

    @BeforeEach
    void reset() {
        auditLog.clear();
        clock.setTime(TestConfig.EPOCH);
    }

    private String issue(String caller, long ttl) throws Exception {
        MvcResult result = mvc.perform(post("/sessions")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"caller\":\"" + caller + "\",\"ttlSeconds\":" + ttl + "}"))
                .andExpect(status().isCreated())
                .andReturn();
        return Json.field(result.getResponse().getContentAsString(), "tokenId");
    }

    @Test
    void missingUnknownExpiredRevokedAndForbiddenReturnDistinctReasons() throws Exception {
        String alice = issue("alice", 10);

        // 未携带凭证 -> 401 MISSING_CREDENTIAL
        mvc.perform(post("/api/access").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"resource\":\"docs\",\"action\":\"read\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.reason").value("MISSING_CREDENTIAL"))
                .andExpect(jsonPath("$.decisionId").exists());

        // 未知凭证 -> 401 UNKNOWN_CREDENTIAL
        mvc.perform(post("/api/access").contentType(MediaType.APPLICATION_JSON)
                        .header("Authorization", "Bearer ghost")
                        .content("{\"resource\":\"docs\",\"action\":\"read\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.reason").value("UNKNOWN_CREDENTIAL"));

        // 合法但无权限 -> 403 ACCESS_DENIED（与访问不存在资源同形态）
        mvc.perform(post("/api/access").contentType(MediaType.APPLICATION_JSON)
                        .header("Authorization", "Bearer " + alice)
                        .content("{\"resource\":\"docs\",\"action\":\"write\"}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.reason").value("ACCESS_DENIED"));
        mvc.perform(post("/api/access").contentType(MediaType.APPLICATION_JSON)
                        .header("Authorization", "Bearer " + alice)
                        .content("{\"resource\":\"nope\",\"action\":\"read\"}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.reason").value("ACCESS_DENIED"));

        // 过期 -> 401 CREDENTIAL_EXPIRED
        clock.advanceSeconds(10);
        mvc.perform(post("/api/access").contentType(MediaType.APPLICATION_JSON)
                        .header("Authorization", "Bearer " + alice)
                        .content("{\"resource\":\"docs\",\"action\":\"read\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.reason").value("CREDENTIAL_EXPIRED"));

        // 撤销 -> 401 CREDENTIAL_REVOKED
        clock.setTime(TestConfig.EPOCH);
        String bob = issue("bob", 600);
        mvc.perform(post("/sessions/" + bob + "/revoke"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.changed").value(true));
        mvc.perform(post("/api/access").contentType(MediaType.APPLICATION_JSON)
                        .header("Authorization", "Bearer " + bob)
                        .content("{\"resource\":\"docs\",\"action\":\"read\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.reason").value("CREDENTIAL_REVOKED"));
    }

    @Test
    void fullHappyPathIssueAccessRenewAccess() throws Exception {
        String alice = issue("alice", 600);
        mvc.perform(post("/api/access").contentType(MediaType.APPLICATION_JSON)
                        .header("Authorization", "Bearer " + alice)
                        .content("{\"resource\":\"docs\",\"action\":\"read\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.allowed").value(true));

        mvc.perform(post("/sessions/" + alice + "/renew").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"ttlSeconds\":900}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.version").value(2))
                .andExpect(jsonPath("$.changed").value(true));

        mvc.perform(get("/admin/audit"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].policyVersion").exists())
                .andExpect(jsonPath("$[0].credentialStatus").exists());
    }

    @Test
    void hotReloadPolicyChangesDecisionsAndRejectsInvalid() throws Exception {
        String alice = issue("alice", 600);

        // 初始允许
        mvc.perform(post("/api/access").contentType(MediaType.APPLICATION_JSON)
                        .header("Authorization", "Bearer " + alice)
                        .content("{\"resource\":\"docs\",\"action\":\"read\"}"))
                .andExpect(status().isOk());

        // 非法策略（重复规则）-> 400，当前策略不变
        String duplicate = "{\"rules\":["
                + "{\"caller\":\"alice\",\"resource\":\"docs\",\"action\":\"read\"},"
                + "{\"caller\":\"alice\",\"resource\":\"docs\",\"action\":\"read\"}]}";
        mvc.perform(put("/admin/policy").contentType(MediaType.APPLICATION_JSON).content(duplicate))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.reason").value("INVALID_POLICY"));

        // 合法热更新：移除 alice 权限
        String denyAll = "{\"rules\":[]}";
        mvc.perform(put("/admin/policy").contentType(MediaType.APPLICATION_JSON).content(denyAll))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.version").value(2));

        mvc.perform(post("/api/access").contentType(MediaType.APPLICATION_JSON)
                        .header("Authorization", "Bearer " + alice)
                        .content("{\"resource\":\"docs\",\"action\":\"read\"}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.reason").value("ACCESS_DENIED"));
    }

    @Test
    void renewingRevokedCredentialIsRejected() throws Exception {
        String bob = issue("bob", 600);
        mvc.perform(post("/sessions/" + bob + "/revoke")).andExpect(status().isOk());
        mvc.perform(post("/sessions/" + bob + "/renew").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"ttlSeconds\":600}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.reason").value("INVALID_CREDENTIAL_OPERATION"));
    }

    /** 极简 JSON 字段提取，避免引入额外依赖。 */
    static final class Json {
        static String field(String body, String name) {
            String key = "\"" + name + "\":\"";
            int start = body.indexOf(key) + key.length();
            int end = body.indexOf('"', start);
            return body.substring(start, end);
        }
    }
}
