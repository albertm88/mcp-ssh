# SSH MCP 1.0.0 需求与验收

状态：**1.0.0 已正式发布（2026-08-09）**。本文定义 1.0.0 交付结果；当前项目版本 `1.0.0`，全部条目已验收（受控跳过项见 release-checklist 标注，由开发者决策接受）。

> **平台支持声明（2026-08-09）**：macOS 为**不支持平台**。本地运行端与远端目标端仅支持 **Windows** 与 **Linux**。macOS 相关条目（FR-02、NFR-04 中 macOS 组合）视为不适用，不作为 1.0.0 门禁。

## 1. 产品边界

- [ ] 面向 MCP 客户端提供完整 SSH 命令、发现、文件和审核能力。
- [ ] 本地运行端与远端目标端支持 **Windows** 与 **Linux**（macOS 明确不支持）。
- [ ] 不删除、不改名当前 14 个工具；参数兼容。返回结果升级按第 4 节执行。
- [ ] 默认传输为 stdio；审核、SSH 身份校验、执行可靠性分别处理。

## 2. 功能需求

### FR-01 现有工具完整保留

| 类别 | 1.0.0 必须提供的工具 |
|---|---|
| 命令 | `ssh_exec`、`ssh_exec_batch` |
| 主机 | `ssh_list_hosts`、`ssh_scan` |
| 文件 | `ssh_upload`、`ssh_download`、`ssh_upload_dir`、`ssh_download_dir` |
| 远端文件系统 | `ssh_list_dir`、`ssh_stat_file`、`ssh_mkdir`、`ssh_remove` |
| 审核 | `ssh_get_review_mode`、`ssh_set_review_mode` |

验收：MCP `tools/list` 精确包含以上 14 个工具；旧参数调用均能通过 schema 校验。

### FR-02 跨平台（Windows + Linux，macOS 不支持）

- [x] 本地端：Windows、Linux 均能安装、启动、读取用户 SSH 配置和密钥（Windows 本机 + WSL2 Ubuntu 实测）。
- [x] 远端端：Windows OpenSSH、Linux OpenSSH 均能执行命令及完成 SFTP 操作（WSL2 sshd 双平台实测）。
- [ ] shell 显式支持 `cmd`、`powershell`/`pwsh`、`sh`、`bash`、`zsh`；自动模式不得依据本地 OS 推断远端 OS。
- [ ] 路径、环境变量、换行和编码由远端适配器处理；SFTP 路径不经本地路径库改写。
- [ ] IPv4 与 IPv6 主机连接可用；`ssh_scan` 对声明支持的地址族有边界测试。

### FR-03 四种审核模式

所有可产生外部影响的工具先生成规范化操作计划，再审核，再执行。审核模式只能由服务配置或 `ssh_set_review_mode` 修改，单次工具参数不能替代审核决定。

| 模式 | 必须行为 |
|---|---|
| `off` | 跳过授权判断并执行；仍执行参数合法性、SSH 身份校验、超时和资源保护。 |
| `whitelist` | 命中启用的结构化规则才放行；未命中则拒绝，并返回规则/原因。 |
| `manual` | 每个操作计划等待人工批准；拒绝、超时或通道不可用均不执行。 |
| `smart` | 确定性规则和智能判断共同给出放行、拒绝或转人工；智能能力不可用或结论不确定时转人工。 |

- [ ] 审核结果绑定操作计划摘要；审核后主机、命令、路径、shell、环境变量或覆盖范围变化必须重新审核。
- [ ] 批处理明确展示全部命令；执行结果逐项关联审核决定。
- [ ] 密码、私钥和环境变量值不进入审核显示或日志；仅展示脱敏值或变量名。
- [ ] `allow_dangerous` 为兼容参数，不得绕过 `manual` 或 `smart` 审核。
- [ ] 每次决策记录 `request_id`、模式、结果、风险、依据、计划摘要、耗时和时间戳。

### FR-04 命令与文件

- [ ] 命令同时排空 stdout/stderr，返回真实退出码；超时或取消后关闭远端 channel，不继续后台失控执行。
- [ ] PTY 默认关闭，仅在调用明确要求或远端适配器确认需要时开启。
- [ ] 单条和批量命令复用相同执行内核；批量保留顺序、`stop_on_error` 语义和逐项结果。
- [ ] 文件/目录通过 SFTP 流式传输；支持覆盖策略、进度、字节数、校验和、临时文件及成功后的原子替换。
- [ ] 上传、下载、列目录、stat、mkdir、remove 在三种远端 OS 上语义一致；递归和覆盖范围进入审核计划。
- [ ] 扫描限制地址数、并发、端口和超时，拒绝超出配置上限的请求，不先展开无界网段。

## 3. 非功能需求

| ID | 要求 | 可验收指标 |
|---|---|---|
| NFR-01 安全 | host key 默认严格校验；首次信任须显式完成；凭据不落日志 | 错误指纹连接 100% 拒绝；凭据扫描无明文命中 |
| NFR-02 可靠性 | 每次调用有 deadline、取消、资源释放和稳定错误码 | 超时后 5 秒内返回；连接/channel/SFTP 无泄漏 |
| NFR-03 效率 | 有界线程池与连接池；批量复用连接；输出/扫描/传输有配额 | 并发压测不超过配置上限；无无界内存增长 |
| NFR-04 兼容 | Python 3.10+；三种本地 OS × 三种远端 OS 测试矩阵 | 发布矩阵全部通过或明确记录受控跳过原因 |
| NFR-05 可观测 | JSONL 审计日志、指标、request_id 贯穿 | 每个调用可由 request_id 还原审核与执行结论 |
| NFR-06 可发布 | 单一版本源、锁文件、wheel/sdist、变更日志、回滚包 | 干净环境安装及回滚演练通过 |

## 4. 结构化返回结果

所有工具返回 MCP 结构化数据；人类可读文本可作为兼容展示，但不得再作为程序判断依据。

```json
{
  "schema_version": "1.0",
  "request_id": "uuid",
  "ok": true,
  "tool": "ssh_exec",
  "host": "alias",
  "status": "succeeded",
  "duration_ms": 123,
  "review": {"mode": "manual", "decision": "approved", "risk": "medium", "reason": "..."},
  "data": {},
  "warnings": [],
  "error": null
}
```

稳定状态：`succeeded`、`failed`、`rejected`、`timed_out`、`cancelled`、`partial`。失败时 `error` 至少包含 `code`、`message`、`retryable`；不得用异常文案或字符串搜索判断业务状态。

工具数据最低要求：

- 命令：`exit_code`、`stdout`、`stderr`、`timed_out`、`truncated`；批量增加逐项结果。
- 扫描：目标范围、探测数、命中主机列表和是否截断。
- 传输：源/目标、文件数、字节数、校验和、跳过/失败项。
- 文件系统：规范化路径、类型、大小、时间、权限（远端可提供时）。
- 审核状态：当前模式和配置摘要；切换结果含旧/新模式。

## 5. 验收测试

| 测试 ID | 完成条件 |
|---|---|
| T-CONTRACT-01 | `tools/list` 快照覆盖 14 个工具；输入 schema 与兼容参数无漂移。 |
| T-CONTRACT-02 | 每个工具的成功、失败、拒绝、超时均符合 1.0 返回 schema。 |
| T-REVIEW-01 | 四模式逐工具覆盖；验证拒绝/超时零副作用及计划摘要防篡改。 |
| T-SEC-01 | 错误 host key、注入型环境变量名、敏感日志、根路径递归删除用例通过。 |
| T-EXEC-01 | 大量 stdout/stderr、非零退出、超时、取消、PTY 开关和批量中断通过。 |
| T-SFTP-01 | 文件/目录双向传输、覆盖、断流恢复、校验和及原子替换通过。 |
| T-PLATFORM-01 | Windows/Linux 本地启动与 Windows/Linux 远端 OS 集成矩阵通过（macOS 为不支持平台，不纳入）。 |
| T-PERF-01 | 连接/线程/扫描/输出配额压测通过，进程内存和句柄回落到阈值内。 |
| T-OPS-01 | 干净安装、升级、监控告警、故障处置和回滚演练通过。 |

## 6. 需求追踪

| 需求 | 架构落点 | 测试 | 运维证据 |
|---|---|---|---|
| FR-01 | `architecture.md` §2、§8 | T-CONTRACT-01 | 发布前工具快照 |
| FR-02 | `architecture.md` §4 | T-PLATFORM-01 | 平台矩阵报告 |
| FR-03 | `architecture.md` §3 | T-REVIEW-01 | 审核决策日志 |
| FR-04 | `architecture.md` §5 | T-EXEC-01、T-SFTP-01 | 调用/资源指标 |
| NFR-01~03 | `architecture.md` §3、§5、§7 | T-SEC-01、T-PERF-01 | 安全与容量基线 |
| NFR-04~06 | `architecture.md` §4、§8 | T-PLATFORM-01、T-OPS-01 | 发布清单、回滚记录 |

### 6.1 交付进展（ssh-mcp-delivery-v1，2026-08-09）

已落地证据：

- FR-01 / T-CONTRACT-01：`tools/list` 精确返回 14 个工具（MCP stdio 实测）；`tests/test_delivery_contract.py` 断言工具名与参数 schema。
- FR-03：审核四模式回归 44 用例保持；拒绝路径返回 `rejected` + `REVIEW_REJECTED`。
- FR-04 / T-SFTP-01：单文件/目录原子传输、字节/sha256 校验、失败清理由 `tests/test_sftp_control.py` 覆盖（fake SFTP）。
- NFR-01：严格 host-key（`host_keys.py` + `RejectPolicy`）已实现，`AutoAddPolicy` 已从执行路径移除；错误指纹连接 100% 拒绝断言在契约测试中。
- NFR-02：命令执行内核沿用上游 monotonic deadline；超时返回 `timed_out` + `EXEC_TIMEOUT`；连接超时/认证失败/网络错误映射为 `CONNECT_TIMEOUT`/`AUTH_FAILED`/`CONNECTION_LOST`。
- NFR-05：envelope 携带 `request_id` 与 `review.plan_id`，审计事件贯穿工具调用。

代码评审修复（2026-08-09 `/review` 结论落地）：

- 非零退出码返回 `failed` + `REMOTE_EXIT_NONZERO`，不再报告为成功。
- 4 个 SFTP 工具的 host-key/连接失败返回稳定 envelope，无裸异常逃逸。
- `ssh_download`/`ssh_download_dir` 成功返回真实 `sha256`。
- 批处理失败时 `ok`/`status`/`error` 一致。
- 输出配额（1 MiB）在 `_read_channel` 实际执行，超限 `OUTPUT_LIMIT`。
- 远端路径拒绝 `.` / `..` 组件（敏感路径正则绕过修复）。
- SHA-256 改为流式分块计算（峰值内存 O(chunk)）。

运行时回归证据（2026-08-09，Windows 本地 × WSL2 远端 `ssh-mcp-wsl-test` + Linux 本地（WSL2 Ubuntu Python 3.14）× Linux 远端 127.0.0.1:2222）：

- `ssh_exec(hostname)` → `succeeded`，exit 0（双平台）。
- 单文件上传/下载 → 上传与下载 `sha256` 完全一致（Windows `a23a9e46…`，Linux `082c8aa3…`），字节数一致。
- 目录上传/下载 2 文件 roundtrip → 内容一致。
- `sleep 3` + `timeout=1` → `timed_out` + `EXEC_TIMEOUT`，失败关闭（Windows 1.41s / Linux 同）。
- 无可信 known_hosts → `HOST_KEY_MISMATCH`（认证前失败关闭，retryable=False）。
- 错误密码 → `AUTH_FAILED`；不可达端口 → `CONNECT_TIMEOUT`；身份文件缺失 → `INVALID_ARGUMENT`（双平台一致）。
- 环境变量值（`hunter2secretvalue` 实测）不入日志/审计，`export K=value` 日志脱敏为 `***`。
- Windows 干净 venv 安装 wheel → site-packages 导入 → 真实调用成功；卸载后 `PackageNotFoundError`。
- Linux（WSL2）`pip install --target` 安装 wheel → 5 模块导入 + 真实调用成功。
- `uvx pip-audit` → No known vulnerabilities found。
- 依赖约束修复：`mcp>=1.2.0,<2.0`（mcp 2.0 已移除 `mcp.server.fastmcp`，Windows/Linux 干净安装均实测解析到 1.29.0）。
- Linux 本地端全量：`compileall` exit 0 + `pytest` 92 passed（Python 3.14.4）。
- **行为边界钩子**：14 工具统一 `_tool_boundary` 钩子，未捕获异常 → 稳定错误码 envelope；MCP schema 完整；钩子专项测试 11 项。
- **重写回归**：server.py 编码事故后完整重写（UTF-8 干净），重写后 103 测试 + WSL2 真实调用全部通过。
- **干净构建**：临时目录独立 `uv build`（wheel+sdist）+ 独立 `pytest` 103 passed。
- **升级演练**：1.0.0 干净安装后旧 `~/.ssh/config` 直接兼容，真实调用成功。
- **并发压测**：≤5 并发 WSL2 稳定（5/5）；更高并发受远端 sshd `MaxStartups` 限流。

受控跳过项（1.0.0 发布时开发者已接受，见 release-checklist 标注）：

- NFR-04：远端 Windows OpenSSH 直连未实测（仅 Windows 本地 + WSL2 远端）。
- NFR-06 / T-OPS-01：从 git 提交 checkout 构建、恢复（配置保留）演练未执行。
- T-EXEC-01 / T-PERF-01：取消、PTY 开关全量、内存/句柄回落未执行。
- T-SEC-01：真实网络断流故障注入未执行（`CONNECTION_LOST` 已由单元层覆盖）。
- ADD 审计（`record_dev_operation`/`query_audit_logs`）：环境无 MCP，降级未落库。
- **macOS：不支持平台，相关矩阵项不适用（非 no-go）。**

## 7. 1.0.0 完成定义

- [x] 以上需求、测试均有自动化证据（`pytest` 103 passed + 双平台运行时回归）；受控跳过项已由开发者决策接受（2026-08-09）。
- [x] 文档、工具 schema、版本号（`pyproject.toml` = `1.0.0`）和发布包来自同一工作区状态。
- [x] 无 P0/P1 缺陷；无未决 P2（评审 12 项 + 运行时 3 项全部修复）。
- [x] 运维负责人（开发者）完成发布决策与验收（本文件 + release-checklist go/no-go 标注）。
- [x] wheel/sdist、校验和、CHANGELOG 和回滚演练记录齐全（见 `docs/release-evidence-1.0.0.md`）。
