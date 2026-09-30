package com.github.lisama569.springbootapisessionauthzjava.web;

import com.github.lisama569.springbootapisessionauthzjava.credential.Credential;
import com.github.lisama569.springbootapisessionauthzjava.credential.CredentialService;
import com.github.lisama569.springbootapisessionauthzjava.web.ApiDtos.IssueRequest;
import com.github.lisama569.springbootapisessionauthzjava.web.ApiDtos.RenewRequest;
import com.github.lisama569.springbootapisessionauthzjava.web.ApiDtos.SessionResponse;
import java.time.Duration;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 凭证签发 / 续期 / 撤销端点（本地演示用，不依赖真实身份服务或真实凭据）。
 */
@RestController
@RequestMapping("/sessions")
public class SessionController {

    private static final long DEFAULT_TTL_SECONDS = 600L;

    private final CredentialService credentialService;

    public SessionController(CredentialService credentialService) {
        this.credentialService = credentialService;
    }

    /** 签发凭证。 */
    @PostMapping
    public ResponseEntity<SessionResponse> issue(@RequestBody IssueRequest request) {
        long ttl = request.ttlSeconds() == null ? DEFAULT_TTL_SECONDS : request.ttlSeconds();
        Credential credential = credentialService.issue(request.caller(), Duration.ofSeconds(ttl));
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(toResponse(credential, true));
    }

    /** 续期凭证。 */
    @PostMapping("/{tokenId}/renew")
    public SessionResponse renew(@PathVariable String tokenId, @RequestBody(required = false) RenewRequest request) {
        long ttl = (request == null || request.ttlSeconds() == null)
                ? DEFAULT_TTL_SECONDS : request.ttlSeconds();
        Credential credential = credentialService.renew(tokenId, Duration.ofSeconds(ttl));
        return toResponse(credential, true);
    }

    /** 撤销凭证（幂等）。 */
    @PostMapping("/{tokenId}/revoke")
    public SessionResponse revoke(@PathVariable String tokenId) {
        boolean changed = credentialService.revoke(tokenId);
        // 撤销后仍返回凭证视图（幂等语义通过 changed 体现）
        Credential credential = credentialService.inspect(tokenId).orElseThrow().credential();
        return toResponse(credential, changed);
    }

    private static SessionResponse toResponse(Credential c, boolean changed) {
        return new SessionResponse(
                c.tokenId(),
                c.caller(),
                c.issuedAt(),
                c.expiresAt(),
                c.version(),
                c.revoked(),
                changed);
    }
}
