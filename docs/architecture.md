# SSH MCP 1.0.0 目标架构

当前实现集中在 `server.py`、`review.py`、`logger.py`。1.0.0 在保留 14 个工具及参数的前提下拆分职责，避免审核、平台适配和 SSH I/O 相互绕过。

## 1. 调用链

```text
MCP tool
  -> 输入校验
  -> Host/Profile + 远端平台解析
  -> 不可变 OperationPlan + digest
  -> ReviewEngine(off/whitelist/manual/smart)
  -> SSH/SFTP Executor
  -> ResultEnvelope
  -> MCP structuredContent + 审计/指标
```

规则：执行器只接收已批准的 `OperationPlan`；执行前再次校验 digest。任何变化回到审核步骤。

## 2. 组件与职责

| 组件 | 单一职责 | 禁止事项 |
|---|---|---|
| `tools` | 保持 14 个 MCP 工具名/参数，转换请求和响应 | 不直接连接 SSH |
| `plans` | 规范化主机、shell、命令、路径、覆盖/递归范围并生成 digest | 不做授权判断 |
| `review` | 四模式决策并输出结构化 `ReviewDecision` | 不执行命令/文件操作 |
| `hosts` | 解析 SSH config、认证来源、host key 策略、远端平台探测 | 不输出凭据 |
| `platforms` | Windows/POSIX shell、环境变量、路径和编码适配 | 不使用本地 OS 猜远端 OS |
| `executors` | 命令 channel、SFTP、扫描、超时、取消、配额 | 不绕过审核 |
| `results` | 1.0 结果 envelope、错误码和兼容文本 | 不从展示文本反推状态 |
| `observability` | JSONL 审计、指标、脱敏和 request_id | 不记录密码/私钥/环境值 |

建议包结构：`src/ssh_mcp/{tools,plans,review,hosts,platforms,executors,results,observability}`；迁移期间旧入口只做转发。

## 3. 审核模型

`OperationPlan` 至少包含：`request_id`、工具、解析后的 `user@host:port`、host key 指纹、远端平台、shell、命令或规范化路径、环境变量名、递归/覆盖范围、配额、创建时间。

`ReviewDecision` 至少包含：模式、`approved/rejected/escalated`、风险、原因、规则/模型版本、计划 digest、决策时间、耗时；人工审核另含审批通道返回的不可伪造关联 ID。

- `off`：直接批准计划，但不关闭输入、身份、超时和资源保护。
- `whitelist`：匹配工具 + 主机 + shell/可执行程序 + 路径 + 操作标志的结构化规则；默认拒绝。
- `manual`：通过独立审批通道展示完整计划；失败关闭（fail closed）。stdio 的 stdin/stdout 保留给 MCP 协议，生产审批不得直接读取协议 stdin。
- `smart`：确定性规则先判定；智能判断只返回建议和理由；不确定/不可用转人工。
- `ssh_set_review_mode` 本身产生审计事件；生产可配置为必须人工批准。

## 4. 跨平台边界

本地平台负责配置目录、密钥/agent、进程启动和本地文件路径；远端平台负责 shell、远端路径、环境语法和文本编码，两者独立组合测试。

| 远端 | 命令适配 | 文件适配 |
|---|---|---|
| Windows OpenSSH | `cmd`、Windows PowerShell、PowerShell 7；环境变量使用对应 shell 语法 | SFTP 路径由远端适配器规范化；盘符/分隔符以真实 OpenSSH 集成测试为准 |
| Linux | `sh`、`bash`、`zsh`；POSIX quoting | SFTP/POSIX 权限和软链接策略 |
| macOS | `sh`、`bash`、`zsh`；POSIX quoting | SFTP/POSIX 权限和软链接策略 |

远端平台来源顺序：Host Profile 显式配置 > 受控探测并缓存 > 无法确认时报错要求指定。不得静默套用错误 shell。

## 5. 执行内核

### 命令

- 单次调用建立 channel；默认无 PTY；并行排空 stdout/stderr。
- deadline 覆盖连接、审核、执行和收尾；取消时关闭 channel/transport 并返回明确状态。
- 输出按字节配额保存；超限标记 `truncated=true`，日志只记长度/摘要。
- 批处理在一个受控连接中顺序执行，每项独立结果；`stop_on_error` 只依据结构化状态/退出码。

### SFTP

- 连接内复用 SFTP session；目录递归使用有界队列。
- 写入目标同目录临时文件，完成后校验字节数/可选 SHA-256，再原子替换。
- 失败保留可识别的临时状态并按策略清理；不得把部分文件报告为成功。
- 软链接、覆盖、权限和时间戳语义显式记录；远端不支持时返回 warning。

### 扫描与连接池

- CIDR 迭代提交，不整体展开；限制最大地址数、并发和总 deadline；IPv4/IPv6 使用匹配 socket。
- 连接池 key 包含主机、端口、用户、认证来源和 host key；设最大数、空闲 TTL、健康检查。
- 阻塞 Paramiko 工作进入有界线程池；MCP 事件循环不得被长调用阻塞。

## 6. 结构化结果与错误

统一 envelope 见 `requirements-1.0.md` §4。`data` 使用按工具定义的模型；兼容文本由同一个模型渲染。

稳定错误码至少包括：

- `INVALID_ARGUMENT`、`UNSUPPORTED_PLATFORM`、`REVIEW_REJECTED`、`REVIEW_TIMEOUT`
- `HOST_KEY_MISMATCH`、`AUTH_FAILED`、`CONNECT_TIMEOUT`、`CONNECTION_LOST`
- `EXEC_TIMEOUT`、`EXEC_CANCELLED`、`REMOTE_EXIT_NONZERO`、`OUTPUT_LIMIT`
- `LOCAL_IO_ERROR`、`REMOTE_IO_ERROR`、`CHECKSUM_MISMATCH`、`RESOURCE_LIMIT`

异常在工具边界统一映射；`message` 供人阅读，自动化只依赖 `code/status/retryable`。

## 7. 安全与可观测

- host key 默认严格验证；新增主机须显式信任指纹，禁止自动接受未知 key。
- 密码仅来自进程注入的秘密源；私钥不复制、不打印；日志统一脱敏。
- 环境变量名按远端 shell 语法白名单校验，值使用对应适配器安全编码。
- 审核控制“是否允许”；参数校验、身份验证、资源限制和数据完整性始终启用。
- 审计日志追加写：request_id、计划摘要、审核、执行结论、耗时、流量、错误码；命令正文按策略摘要化。
- 指标：调用数/失败率/拒绝率/超时率、审核等待、连接/命令延迟、池占用、传输字节、输出截断、资源拒绝。

## 8. 迁移与交付顺序

1. 冻结 14 工具的 `tools/list` 快照和现有输入 schema。
2. 引入结果模型/错误码，保留兼容文本；批处理改用结构化结果判断。
3. 引入 `OperationPlan` 与统一审核入口，移除 `allow_dangerous` 绕过能力。
4. 拆出 host/platform/exec/SFTP 适配层并完成三平台矩阵。
5. 加入 deadline、取消、配额、连接池、流式传输和完整性校验。
6. 完成单元、契约、集成、故障注入、性能及回滚测试后发布 1.0.0。

每一步均保持 MCP 服务可启动；只在第 6 步同时切换版本号、发布包和文档。

## 9. 本轮自动化基础实现状态

本轮 `ssh-mcp-automation-foundation-v1` 已完成审核计划基础的代码实现：

- `review.py` 的 `ReviewContext` 为不可变对象，计划摘要覆盖工具、主机、命令、shell、环境变量名、环境值摘要、本地/远端路径、递归和覆盖范围。
- 无效工具、缺少主机、非法环境变量名和非法操作标志在审核器入口失败关闭。
- `ssh_exec`、批处理、网段扫描、mkdir、文件上传/下载、目录上传/下载和删除操作在连接或探测前使用完整审核计划。
- 审核日志只记录环境变量名数量和计划摘要，不记录环境变量值。
- pytest 开发依赖已声明；审核回归测试当前提供可复现的静态证据。
- 已在受控 WSL2 端点 `ssh-mcp-wsl-test` 完成一次性运行时证据：命令、批处理、扫描、单文件和目录 SFTP roundtrip 均成功；默认 whitelist 对未授权上传失败关闭。
- MCP stdio handshake 返回 14 个工具；端到端 `ssh_exec(hostname)` 调用返回成功并得到 WSL 主机名。

本轮明确未完成的能力，不得以本轮测试结果替代运行时证据：

- `server.py` 的严格 host-key 校验和未知指纹显式信任流程。
- 命令执行内核的默认关闭 PTY、取消、输出配额和统一结构化结果。
- SFTP 临时文件、校验和、原子替换、断点恢复和连接池。
- 错误 host-key、认证失败、Windows/Linux/macOS 本地端与远端组合和网络故障注入。
- 命令执行 deadline/取消：WSL2 实测 `sleep 2` 配置 `timeout=1` 未失败关闭，必须由下一命令执行内核 Plan 修复。

命令执行 deadline 已在下一阶段 Plan 中修复：读取、退出状态和批处理共享 monotonic deadline；超时关闭 client，WSL2 和 MCP timeout 回归均返回失败，未发现残留 sleep 进程。

---

## 10. 本轮交付实现状态（ssh-mcp-delivery-v1）

本轮交付闭环已落地以下能力，对应 `.codex/plans/2026-08/09/ssh-mcp-delivery-plan-v1.md`：

### 10.1 严格 host-key（Review P1 #2）

- 新增 `host_keys.py`：`apply_host_key_policy()` 加载系统 known_hosts + 显式 `SSH_KNOWN_HOSTS`，默认 `paramiko.RejectPolicy`。
- `server.py:_connect()` 已移除 `AutoAddPolicy`；未知/错误指纹在认证前失败关闭，返回 `HOST_KEY_MISMATCH`。
- 无可信 known_hosts 来源时同样失败关闭；不提供自动接受 key 的工具。
- 指纹诊断只含 host/port/安全指纹，不包含密码、私钥内容或环境值。

### 10.2 统一结果/错误契约（Review P1 #3）

- 新增 `results.py`：`ResultEnvelope`（schema_version/request_id/ok/tool/host/status/duration_ms/review/data/warnings/error/text）。
- 稳定状态 6 个、稳定错误码 14 个；`retryable` 由错误码集合推导。
- 14 个 MCP 工具返回 envelope dict（FastMCP 渲染为结构化 JSON 文本，含兼容 `text` 字段）；工具名与输入参数保持兼容。
- 批处理 `stop_on_error` 依据结构化 `data.items[].status` 判断，不再搜索展示文本首行。

### 10.3 SFTP 可靠原子传输（Review P1 #4）

- `_sftp_put_atomic`：目标同目录临时名 → 流式写入 → 字节数 + SHA-256 校验 → `posix_rename` 原子替换；失败清理临时文件。
- `_sftp_get_atomic`：本地同目录临时名 → 远端 size 校验 → 原子替换；失败不覆盖已有文件。
- 目录上传/下载走 `_sftp_bounded_walk`/`_local_bounded_walk`：拒绝软链接逃逸，限制文件数/总字节/递归深度。
- 部分失败返回 `partial` 并列出跳过/失败项，不把部分传输报告为 `succeeded`。

### 10.4 资源限制（Review P2 #5）

- 单文件 100 MiB、目录 2000 文件 / 1 GiB / 深度 32、扫描地址 4096，`off` 审核模式也不能关闭。

### 10.5 交付证据与未验证矩阵

- 已通过：`python -m compileall -q`（exit 0）、`uv run pytest -q`（103 passed）、MCP stdio handshake + `tools/list` 14 工具 + 一次 envelope 调用。
- 新增测试：`tests/test_delivery_contract.py`（14 工具、envelope、错误码、host-key 契约）、`tests/test_sftp_control.py`（fake SFTP 原子/回滚/边界/清理）、`tests/test_boundary.py`（行为边界钩子专项，11 项）。
- **未验证（保留 release no-go）**：macOS（声明为不支持平台）、12 CI 组合、真实断流注入、从 git 提交 checkout 构建、恢复（配置保留）演练。

### 10.6 行为边界钩子（`_tool_boundary`）

- 所有 14 个 MCP 工具经 `@_tool_boundary` 装饰器包装，统一把未捕获异常映射为稳定错误 envelope（`HOST_KEY_MISMATCH`/`AUTH_FAILED`/`CONNECT_TIMEOUT`/`CONNECTION_LOST`/`RESOURCE_LIMIT`/`CHECKSUM_MISMATCH`/`EXEC_TIMEOUT`/`REMOTE_IO_ERROR`）。
- 保证"所有工具 100% 返回 ResultEnvelope"契约——工具内部遗漏的错误分支不会以裸异常逃逸 MCP 边界。
- 钩子由 `functools.wraps` 保留原签名与 FastMCP schema（MCP `tools/list` 实测 `ssh_exec` 6 参数完整）。
- 工具内部仍保留业务精确错误映射（exit_code、sha256、batch items 等），钩子作为兜底。
