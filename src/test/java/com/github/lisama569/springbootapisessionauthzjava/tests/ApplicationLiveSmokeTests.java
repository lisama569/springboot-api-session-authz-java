package com.github.lisama569.springbootapisessionauthzjava.tests;

import static org.assertj.core.api.Assertions.assertThat;

import com.github.lisama569.springbootapisessionauthzjava.support.TestConfig;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

/** 真实启动 HTTP 服务跑通 签发→访问→撤销→拒绝 全流程。 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Import(TestConfig.class)
class ApplicationLiveSmokeTests {

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate rest;

    private String url(String path) {
        return "http://localhost:" + port + path;
    }

    @Test
    void issueAccessRevokeDenyFlowOverHttp() {
        // 1) 未携带凭证 -> 401
        HttpHeaders jsonHeaders = new HttpHeaders();
        jsonHeaders.setContentType(MediaType.APPLICATION_JSON);
        ResponseEntity<String> noCred = rest.exchange(
                url("/api/access"),
                HttpMethod.POST,
                new HttpEntity<>(accessBody("docs", "read"), jsonHeaders),
                String.class);
        assertThat(noCred.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(noCred.getBody()).contains("MISSING_CREDENTIAL");

        // 2) 签发
        ResponseEntity<String> issued = rest.exchange(
                url("/sessions"),
                HttpMethod.POST,
                new HttpEntity<>(
                        "{\"caller\":\"alice\",\"ttlSeconds\":600}", jsonHeaders),
                String.class);
        assertThat(issued.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        String token = JsonField.get(issued.getBody(), "tokenId");

        // 3) 带凭证访问被允许
        ResponseEntity<String> allowed = exchangeAccess(token, "docs", "read");
        assertThat(allowed.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(allowed.getBody()).contains("\"allowed\":true");

        // 4) 越权动作 -> 403
        ResponseEntity<String> forbidden = exchangeAccess(token, "docs", "write");
        assertThat(forbidden.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(forbidden.getBody()).contains("ACCESS_DENIED");

        // 5) 撤销后 -> 401 CREDENTIAL_REVOKED
        rest.postForEntity(url("/sessions/" + token + "/revoke"), null, String.class);
        ResponseEntity<String> revoked = exchangeAccess(token, "docs", "read");
        assertThat(revoked.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(revoked.getBody()).contains("CREDENTIAL_REVOKED");
    }

    private ResponseEntity<String> exchangeAccess(String token, String resource, String action) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBearerAuth(token);
        return rest.exchange(
                url("/api/access"),
                HttpMethod.POST,
                new HttpEntity<>(accessBody(resource, action), headers),
                String.class);
    }

    private static String accessBody(String resource, String action) {
        return "{\"resource\":\"" + resource + "\",\"action\":\"" + action + "\"}";
    }

    static final class JsonField {
        static String get(String body, String name) {
            String key = "\"" + name + "\":\"";
            int start = body.indexOf(key) + key.length();
            return body.substring(start, body.indexOf('"', start));
        }
    }
}
