package com.github.lisama569.springbootapisessionauthzjava.authz;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import org.springframework.stereotype.Component;

/** 线程安全的内存判定记录簿，用于本地验证与测试断言。 */
@Component
public class AuditLog {

    private final CopyOnWriteArrayList<Decision> decisions = new CopyOnWriteArrayList<>();

    public void append(Decision decision) {
        decisions.add(decision);
    }

    public List<Decision> all() {
        return List.copyOf(decisions);
    }

    public void clear() {
        decisions.clear();
    }
}
