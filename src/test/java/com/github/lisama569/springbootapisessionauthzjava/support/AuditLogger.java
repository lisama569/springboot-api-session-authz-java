package com.github.lisama569.springbootapisessionauthzjava.support;

import com.github.lisama569.springbootapisessionauthzjava.authz.Decision;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 测试日志工具：统一打印调用方、动作、凭证状态、策略版本与判定结果，
 * 便于失败时定位与人工核对。
 */
public final class AuditLogger {

    private static final Logger log = LoggerFactory.getLogger("AUTHZ-TEST");

    private AuditLogger() {
    }

    public static void log(Decision d) {
        log.info(
                "[decision] caller={} resource={} action={} token={} credentialStatus={} "
                        + "policyVersion={} outcome={} reason={} decisionId={}",
                d.caller(),
                d.resource(),
                d.action(),
                d.tokenId(),
                d.credentialStatus(),
                d.policyVersion(),
                d.outcome(),
                d.reason(),
                d.decisionId());
    }

    public static void banner(String title) {
        log.info("==== {} ====", title);
    }
}
