# springboot-api-session-authz-java

一套**不依赖外部身份服务、不使用真实凭据**的本地可验证「接口访问控制 + 会话凭证」机制，
构建于 Spring Boot 3.4 / Java 21 之上。支持：

- 按 **调用方 / 资源动作 / 授权策略** 做访问判定；
- 会话凭证的 **签发、续期、撤销**，并对并发做串行化保护；
- 授权策略的 **运行期原子热更新**（版本化、不可变快照、乐观并发控制）；
- 可区分的失败原因，且**不通过响应差异泄露资源是否存在**；
- 可复现的 **过期时间边界**（时钟可在测试中替换）。

---

## 1. 快速开始

```bash
# 运行全部测试（20 个，含并发、时钟边界、热更新、真实 HTTP 冒烟）
mvn test

# 启动服务（application.properties 中 server.port=0，默认随机端口；
# 本地手动验证时可改成固定端口，如 server.port=8080）
mvn spring-boot:run
```

服务内置一份种子策略（版本 1）：

| caller | resource | action |
|--------|----------|--------|
| alice  | docs     | read   |
| bob    | docs     | read   |
| bob    | docs     | write  |

### 手动验证示例（curl）

```bash
BASE=http://localhost:8080

# 1) 签发凭证（默认 TTL 600 秒，可通过 ttlSeconds 指定 1~86400 秒）
TOKEN=$(curl -s -X POST $BASE/sessions -H 'Content-Type: application/json' \
  -d '{"caller":"alice","ttlSeconds":600}' | sed -n 's/.*"tokenId":"\([^"]*\)".*/\1/p')

# 2) 携带凭证访问 -> 200 allowed=true
curl -s -X POST $BASE/api/access -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $TOKEN" -d '{"resource":"docs","action":"read"}'

# 3) 已认证但无权限 -> 403 reason=ACCESS_DENIED
curl -i -X POST $BASE/api/access -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $TOKEN" -d '{"resource":"docs","action":"write"}'

# 4) 续期（版本号 +1）
curl -s -X POST $BASE/sessions/$TOKEN/renew -H 'Content-Type: application/json' -d '{"ttlSeconds":900}'

# 5) 撤销（幂等，changed 表示本次是否真正改变状态）
curl -s -X POST $BASE/sessions/$TOKEN/revoke

# 6) 查询当前策略 / 查询全部判定记录
curl -s $BASE/admin/policy
curl -s $BASE/admin/audit
```

---

## 2. HTTP API

### 会话凭证 `/sessions`

| 方法 & 路径 | 说明 | 关键语义 |
|---|---|---|
| `POST /sessions` | 签发凭证 | body: `{"caller":"alice","ttlSeconds":600}`；`ttlSeconds` 可省，默认 600，范围 1~86400 |
| `POST /sessions/{tokenId}/renew` | 续期 | 仅当凭证当前**未撤销且未过期**才成功；成功后版本号 +1、`issuedAt/expiresAt` 以续期时刻重算 |
| `POST /sessions/{tokenId}/revoke` | 撤销 | **幂等**；响应 `changed=true/false` 表示本次调用是否真正改变状态 |

凭证响应字段：`tokenId, caller, issuedAt, expiresAt, version, revoked, changed`。

### 受保护访问 `POST /api/access`

- 请求头：`Authorization: Bearer <tokenId>`（可选）、`X-Caller-Hint`（仅记录，不参与信任）。
- 请求体：`{"resource":"docs","action":"read"}`。
- 成功：`200 {"allowed":true,"decisionId":"...","message":"..."}`。
- 失败：统一错误体（见下）。

### 策略管理 `/admin/policy`

| 方法 & 路径 | 说明 |
|---|---|
| `GET /admin/policy` | 查询当前生效策略版本与完整规则 |
| `PUT /admin/policy` | 原子替换整套策略；body: `{"rules":[{caller,resource,action}...],"expectedVersion":1}`。`rules` 允许为空数组（全部拒绝）；`expectedVersion` 可省，提供时做乐观并发控制 |

### 判定记录 `GET /admin/audit`

返回服务启动以来全部判定记录（本地验证/测试观察用）。

---

## 3. 鉴权流程与错误语义

每次请求进入 `DecisionService.decide(...)`，按以下**固定优先级**判定。
判定开始即抓取一次当前策略快照，整个判定固定使用该版本：

1. **未携带凭证** → `401`，`reason=MISSING_CREDENTIAL`
2. **凭证未知** → `401`，`reason=UNKNOWN_CREDENTIAL`
3. **凭证已撤销** → `401`，`reason=CREDENTIAL_REVOKED`（撤销优先于过期）
4. **凭证已过期** → `401`，`reason=CREDENTIAL_EXPIRED`
5. 已认证但策略未授权该 `(caller, resource, action)` → `403`，`reason=ACCESS_DENIED`
6. 其余 → `200 allowed=true`

统一错误体形态（认证类与授权类结构完全一致，仅 HTTP 状态码与 `reason` 不同）：

```json
{
  "error": "access_denied",
  "reason": "ACCESS_DENIED",
  "decisionId": "88ba60f2-...",
  "message": "已认证但无权执行该操作",
  "timestamp": "2026-10-01T00:00:00Z"
}
```

### 为什么不会泄露「资源是否存在」

受保护接口把 `resource/action` 作为**请求参数**而非路由路径，服务端不区分
「资源不存在」与「资源存在但无权」：二者都走到同一条策略匹配逻辑，返回
**完全相同的状态码（403）、相同的响应体结构、相同的 `ACCESS_DENIED` 原因**。
调用方只能区分「认证层面」的失败（401 四种 reason）与「授权层面」的失败（403），
无法据此探测资源是否存在。

---

## 4. 凭证生命周期与并发保障

实现见 `credential/CredentialService`。

- 存储为 `ConcurrentHashMap<tokenId, Entry>`，每个 `Entry` 是该凭证专属的可变持有者。
- **同一凭证的续期/撤销在该 `Entry` 的监视器上串行执行**，因此：
  - 多个并发续期不会丢失更新也不会重复计数——每次成功续期 `version` 恰好 +1；
  - 「续期 vs 撤销」竞争时，撤销一旦提交，后续续期全部被拒绝，**凭证无法被复活/越权放行**；
  - 撤销前成功的续期可能生效，撤销后的续期必然失败，二者数量互补；
  - 读操作（`inspect`）在同一把锁上取快照，不会读到半更新状态，**有效凭证不会被误判失效**。
- **撤销幂等**：重复撤销返回 `changed=false`，不改变版本与时间。
- **过期边界稳定**：`now >= expiresAt` 即判为过期（`expiresAt` 当刻已过期），前一秒仍有效。
  时钟来自可替换的 `TimeSource`，测试用 `MutableTimeSource` 精确设定时间，边界可复现。
- TTL 合法区间 `[1s, 24h]`，非法 TTL 直接 400 拒绝。

---

## 5. 策略版本与生效边界

实现见 `policy/PolicyService`。

- 策略是不可变记录 `Policy(version, List<PolicyRule>)`，规则列表 `List.copyOf` 防御性拷贝。
- 持有方式为 `AtomicReference<Policy>`：`current()` 永远返回**某个完整版本**，
  切换期间的每个请求只能看到**完整的旧策略或完整的新策略之一**，不会看到混合/半成品。
- 替换采用「**先校验、后发布**」：字段为空、规则重复（冲突）、`null` 等非法策略
  在构造新快照阶段即抛 `InvalidPolicyException`，**当前生效策略完全不受影响**。
- 版本号由服务端单调递增；可带 `expectedVersion` 做乐观并发控制，不匹配返回 `409 POLICY_VERSION_CONFLICT`。
- **已完成的判定不可追溯改写**：`Decision` 记录在判定时就固化了 `policyVersion`，
  即使随后策略切换，历史判定与审计记录仍保持其当时版本的结论。

---

## 6. 可观测性 / 判定日志

每次判定都会：写入内存 `AuditLog`（`GET /admin/audit` 可查），并输出一条结构化日志
（logger 名 `AUTHZ-AUDIT`），包含：

```
caller=... action=... resource=... token=... credentialStatus=VALID
policyVersion=1 outcome=DENY reason=ACCESS_DENIED decisionId=...
```

测试中 `AUTHZ-TEST` logger 会额外打印调用方、动作、凭证状态、策略版本与判定结果。

---

## 7. 本地验证（测试地图）

测试统一通过可注入的 `MutableTimeSource` 控制时间，无需等待真实时间流逝。

| 测试类 | 覆盖场景 |
|---|---|
| `CredentialConcurrencyTests` | 16 线程并发续期版本号精确；32 线程续期/撤销竞争，撤销后不可复活、撤销幂等 |
| `CredentialClockBoundaryTests` | `expiresAt-1 / expiresAt / expiresAt+1` 边界；过期不可续期；续期后边界仍稳定；非法 TTL |
| `PolicyHotReloadTests` | 原子发布与版本递增；非法/重复/null 策略被拒绝且不影响当前策略；乐观版本冲突 409；16 读者并发只读完整策略 |
| `DecisionServiceTests` | 五种失败原因可区分；无权限与资源不存在同形态；旧判定不被追溯改写；撤销即时生效 |
| `WebApiIntegrationTests` | MockMvc 端到端：401 四种 reason、403、热更新改变判定、撤销后续期 400、审计可查 |
| `ApplicationLiveSmokeTests` | 真实随机端口启动，HTTP 全流程：未认证→签发→放行→403→撤销→401 |

```bash
mvn test                      # 全部
mvn test -Dtest=PolicyHotReloadTests   # 单个测试类
```

---

## 8. 代码结构

```
time/        TimeSource（可替换时钟）、SystemTimeSource
credential/  Credential(不可变)、CredentialStatus、CredentialService（签发/续期/撤销）、CredentialOperationException
policy/      PolicyRule、Policy(不可变快照)、PolicyService（原子热更新/校验）、InvalidPolicyException
authz/       DecisionService（判定编排）、Decision、DecisionOutcome、DenialReason、AuditLog
web/         AccessController、SessionController、PolicyAdminController、ApiDtos、GlobalExceptionHandler
test/support MutableTimeSource、TestConfig、AuditLogger
```

> 说明：`/sessions` 与 `/admin/*` 为本地演示端点，未叠加额外管理鉴权；
> 生产使用时应在其前放置独立的管理面认证。数据全部存于内存，重启即清空。
