# springboot-api-session-authz-java

一个**不依赖任何外部身份服务或真实凭据**的本地可验证鉴权示例：基于 Spring Boot 的接口访问控制
（Authorization）+ 会话凭证（Session Credential）机制。覆盖凭证签发 / 续期 / 撤销、
按调用方与资源动作的策略判定、策略运行期热更新，以及并发续期 / 撤销下的一致性保证。

## 1. 总体鉴权流程

```
HTTP 请求
  │
  ▼
AuthInterceptor（仅拦截 /api/resources/**）
  │  1. 从 Authorization: Bearer <token> 提取凭证（缺失/方案错误 → 视为无凭证）
  │  2. 从 URI 提取资源类型，按 HTTP 方法映射动作
  │        GET/HEAD→READ   POST/PUT/PATCH→WRITE   其他→DELETE
  │  3. 调用 AuthorizationService.decide(...)
  ▼
AuthorizationService
  │  a. 读取【一次】当前策略快照 Policy（不可变）
  │  b. 校验凭证状态（ABSENT/UNKNOWN/VALID/EXPIRED/REVOKED）
  │  c. 仅当 VALID 时，在该策略快照上评估 (caller, resource, action)
  │  d. 输出结构化判定 AuthzDecision，并打印判定日志
  ▼
放行 → Controller 处理；拒绝 → 统一 404 + JSON 错误码
```

判定模型为**默认拒绝（fail-closed）**：凭证无效或策略无显式 ALLOW 规则，一律拒绝。

## 2. 错误语义：原因可区分，但不泄露资源是否存在

这是本项目最关键的安全约定。对于受保护资源（`/api/resources/**`），
**所有拒绝场景返回完全相同的 HTTP 状态码 `404`、相同的响应体结构与文案**，
调用方通过响应体中的机器可读字段 `error` 区分失败原因，但**无法从状态码/响应差异推断资源是否存在**：

| 场景 | HTTP | 响应体 `error` | 含义 |
|---|---|---|---|
| 未携带凭证 | 404 | `NO_CREDENTIAL` | 没有 Authorization 头或不是 Bearer 方案 |
| 凭证无法识别 | 404 | `INVALID_CREDENTIAL` | 令牌不存在（含伪造） |
| 凭证已过期 | 404 | `CREDENTIAL_EXPIRED` | 当前时间已到/超过 `expiresAt` |
| 凭证已撤销 | 404 | `CREDENTIAL_REVOKED` | 令牌被显式撤销 |
| 已认证但无权限 | 404 | `ACCESS_DENIED` | 策略未授权（默认拒绝） |

响应体统一为：

```json
{ "error": "CREDENTIAL_EXPIRED", "message": "resource not found" }
```

说明：

- 即使资源真实存在，未授权访问也是 404；即使资源不存在，未授权访问的响应与前者**逐字节一致**
  （集成测试 `allDenyPathsReturnIdentical404ShapeButDistinctErrorCodes` 对此做了断言）。
- “无法识别凭证”归入 404 而非 401，同样是为了避免资源探测差异。
- 认证原因与授权原因互不混淆：凭证类问题在策略评估之前短路；`ACCESS_DENIED` 只在凭证 VALID 时出现。

凭证生命周期管理接口（见下）使用常规语义表达操作结果：续期冲突返回 409，
令牌未知返回 404，重复撤销幂等返回 200 + `ALREADY_REVOKED`。

## 3. 会话凭证

- 令牌为 256 位密码学随机数的十六进制串（`SecureRandom`），服务端内存保存，无外部依赖。
- 每个令牌对应一条**不可变状态快照**：`token/caller/issuedAt/expiresAt/revoked/revokedAt/renewedTimes`。
- 过期边界是确定的：`now < expiresAt` 有效；**`now == expiresAt` 即视为过期**。
  生产用系统时钟（`SystemAuthClock`），测试用可精确推进/回拨的 `MutableClock`，边界可复现。
- 默认 TTL 由 `authz.session.ttl-seconds`（默认 300s）配置；单次 TTL 必须为正且 ≤ 86400s。

### 凭证接口（本地开发设施，无鉴权拦截）

| 方法与路径 | 说明 |
|---|---|
| `POST /api/sessions` | 签发：`{"caller":"alice","ttlSeconds":300}`（ttlSeconds 可省略）→ 201 |
| `GET  /api/sessions/{token}` | 查询状态；未知 → 404 |
| `POST /api/sessions/{token}/renew` | 续期：`{"ttlSeconds":600}`（可省略）→ 200 `result=RENEWED`；过期/撤销 → 409；未知 → 404 |
| `DELETE /api/sessions/{token}` | 撤销：首次 → 200 `REVOKED`；重复 → 200 `ALREADY_REVOKED`；未知 → 404 |

## 4. 授权策略：版本与生效边界

- 策略是不可变快照 `Policy(version, rules[])`，规则为 `(caller, resource, action, effect)`。
- 初始版本为 **v1 种子策略**（`PolicyService.seedPolicy()`）：
  - `alice`：`docs` 的 READ/WRITE/DELETE 全部 ALLOW，`reports` 仅 READ；
  - `bob`：`docs`、`reports` 仅 READ；`carol`：`docs` 仅 READ；其余默认拒绝。
- 热更新接口 `PUT /api/policies/current` 采用**完整规则集替换 + 乐观版本号**：
  请求体 `{"expectedVersion":1,"rules":[...]}`；只有 `expectedVersion == 当前版本` 才生效，
  新版本号 = 当前版本 + 1（单调递增）。
- 生效边界：
  - 一次请求只读取一次策略快照，因此**每个请求只能看到完整的旧版本或完整的新版本**，
    绝不会看到半更新状态；
  - 新规则先做合法性/冲突校验（空字段、null 枚举、同一 `(caller,resource,action)` 重复），
    非法请求返回 409 `INVALID_POLICY`，**当前生效策略完全不受影响**；
  - 旧快照对象不被修改，因此**旧策略下已完成的判定不会被追溯改写**；
  - 并发替换同一版本：恰好一个成功，其余因版本冲突失败（CAS + 版本双重保证）。

## 5. 并发保障

凭证状态全部保存在 `ConcurrentHashMap`，变更通过 `replace(key, old, new)` 的 **CAS** 完成：

- **并发撤销**：只有第一个 CAS 返回 `REVOKED`，其余为 `ALREADY_REVOKED`，撤销恰好生效一次；
- **并发续期**：每次都基于最新快照原子地延长到期时间并自增计数，不丢失、不重复、无中间失效态；
- **续期与撤销竞争**：撤销一旦成功，后续续期一律 `REVOKED`，凭证不可能被“续期复活”，不会越权放行；
- **查找无副作用**：`lookup/statusOf` 只读快照，不会把有效凭证误判为失效；
- 撤销状态优先于过期：撤销后即使时间越过到期点，状态仍稳定为 `REVOKED`，原因可区分。

## 6. 可观测日志

每次判定打印一行结构化日志，包含**调用方、动作、资源、凭证状态、策略版本、判定结果**：

```
authorization decision | caller=bob | action=WRITE | resource=docs | credential=VALID | policyVersion=1 | result=DENY(ACCESS_DENIED)
request denied | httpStatus=404 | errorCode=ACCESS_DENIED
```

测试运行时同样输出这些字段，便于追踪每个用例的判定依据。

## 7. 本地验证

要求 JDK 21+、Maven 3.9+。

```bash
# 运行全部 16 个测试（并发续期/撤销、权限边界、策略热更新、时钟边界、HTTP 端到端）
mvn test

# 启动服务（随机端口，观察日志中的 Tomcat started on port）
mvn spring-boot:run
```

手工冒烟（假设端口为 8080，可在启动日志中找到实际端口）：

```bash
# 1) 签发凭证
TOKEN=$(curl -s -X POST localhost:8080/api/sessions -H 'Content-Type: application/json' \
  -d '{"caller":"alice","ttlSeconds":300}' | jq -r .token)

# 2) 访问受保护资源：200
curl -i localhost:8080/api/resources/docs/123 -H "Authorization: Bearer $TOKEN"

# 3) 不带凭证：404 + NO_CREDENTIAL（不暴露资源是否存在）
curl -i localhost:8080/api/resources/docs/123

# 4) 撤销后访问：404 + CREDENTIAL_REVOKED
curl -s -X DELETE localhost:8080/api/sessions/$TOKEN
curl -i localhost:8080/api/resources/docs/123 -H "Authorization: Bearer $TOKEN"

# 5) 查看 / 热更新策略
curl -s localhost:8080/api/policies/current | jq .
curl -s -X PUT localhost:8080/api/policies/current -H 'Content-Type: application/json' \
  -d '{"expectedVersion":1,"rules":[{"caller":"bob","resource":"docs","action":"WRITE","effect":"ALLOW"}]}'
```

### 测试清单

| 测试类 | 覆盖点 |
|---|---|
| `SessionConcurrencyTest` | 24 线程并发续期不丢失；16 线程并发撤销恰好一次；24 续期 + 8 撤销混合竞争不复活凭证 |
| `SessionClockBoundaryTest` | 到期前/到期时刻/到期后边界稳定；过期不可续期；撤销优先于过期；ABSENT 与 UNKNOWN 区分 |
| `AuthorizationBoundaryTest` | 种子策略权限边界；五种拒绝原因两两可区分；默认拒绝 |
| `PolicyHotReloadTest` | 非法/冲突规则拒绝且不影响当前版本；过期版本号拒绝；16 路并发替换只成功一次；旧快照判定不被追溯 |
| `WebApiIntegrationTest` | 五种拒绝的 404 响应逐字节同构；热更新经 HTTP 立即生效；续期/撤销 HTTP 语义 |

## 8. 代码结构

```
clock/    AuthClock 抽象 + 系统时钟实现（测试提供 MutableClock）
domain/   Action/Effect/CredentialStatus/DenyReason 枚举，Policy/PolicyRule/SessionInfo/AuthzDecision 值对象
session/  SessionService：签发、快照查找、CAS 续期/撤销
policy/   PolicyService：不可变策略快照、乐观版本热更新、规则校验
authz/    AuthorizationService（判定）、AuthInterceptor（HTTP 拦截与统一错误响应）
web/      ResourceController（受保护资源）、SessionController、PolicyAdminController、全局异常处理
config/   拦截器注册
```

> 注意：`/api/sessions/**` 与 `/api/policies/**` 是**本地开发管理设施**，刻意不经过鉴权拦截器，
> 生产环境应放在内网或自行加管理面保护。
