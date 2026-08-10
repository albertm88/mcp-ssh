# Changelog

All notable changes are recorded here. The project follows Semantic Versioning.

## [1.0.1] - 2026-08-10（质量与安全加固）

### Security

- **防御纵深（defense-in-depth）**：`_DANGEROUS_COMMANDS`/`_INJECTION_PATTERNS` 从死代码接线到 `_validate_command`——命令注入特征检测与危险命令拦截在**所有审核模式（含 off）**生效，不可绕过；危险命令仅在 `allow_dangerous=True` 时豁免，注入特征无豁免。
- **fork bomb 检测加固**：`_DANGEROUS_COMMANDS` 正则修复，可匹配 `:(){:|:&};:` 等无空格变体（此前仅匹配带空格形式）。

### Fixed

- **空路径失败关闭**：`ssh_list_dir`/`ssh_stat_file`/`ssh_mkdir`/`ssh_remove` 空/空白 `remote_path` 返回 `INVALID_ARGUMENT`，不再尝试连接或执行 `ls ''` 等命令。
- **`ssh_list_dir` 解析修复**：条目 name 从 `HH:MM` 时间列后正确提取（历史错位导致 `.`/`..` 过滤失效），并剥离行尾 `\r`（CRLF 残留）。
- **mypy 零错误基线**：修复 8 个类型错误（`Optional` 默认值、缺失 `host` 参数、重复 `main()` 定义）。

### Quality

- 新增离线回归测试：`tests/test_fs_guards.py`（10 用例，空路径守卫与 list 解析）、`tests/test_command_structure.py`（64 用例，POSIX shell 包装/注入正则/输入边界/环境计划/batch 结构）。
- 测试总数 122 → 196；WSL2 真实 E2E 全绿（hostname/SFTP roundtrip/超时/防御纵深故障注入）。

## [Unreleased] - 2026-08-09（候选变更）

### Added

- `ssh_set_review_mode` 的 `mode` 参数增加 enum 枚举约束（`off`/`whitelist`/`manual`/`smart`），使所有 MCP 客户端能从工具 schema 看到 4 个可选审核模式（此前 `mode` 为自由字符串，客户端无法从 schema 识别 manual 等模式）。

### 前序候选变更

- **manual 审核多通道自动适配**：`manual` 模式按客户端能力自动选择人工确认通道——优先 MCP Elicitation 弹框（客户端声明 `elicitation` capability，VS Code/Claude Code/Claude Desktop/Trae），回退本地终端 `isatty()`，两者都不可用则 fail-closed 拒绝并提示切换模式。`SSH_REVIEW_MANUAL_CHANNEL=elicit|local|auto` 可强制覆盖（默认 auto）。SSH 执行类工具注入 MCP Context 供弹框使用；新增 `manual_confirm_requested`/`manual_confirm_result`/`manual_channel_fallback` 审计事件。
- 新增 `ssh_get_audit_logs` MCP 工具：只读查询最近行为日志（含目标机器 host、登录用户名 username、时间戳、行为函数 tool、含参内容 args、status、耗时），支持按 host/tool/since_minutes 过滤与 limit 上限；args 脱敏（`export K=V` 值 → `***`），单条 args 500 字符截断、总输出 200KB 上限；供 AI 直接分析。日志默认 `~/.ssh/mcp-ssh.log`（`SSH_LOG_FILE` 可覆盖）。

### Fixed

- `ssh_set_review_mode` 移除运行时切换授权门槛：`ReviewEngine.set_mode` 不再需要 `authorized` 参数，`ReviewConfig` 移除 `allow_runtime_switch` 配置项与 `SSH_REVIEW_ALLOW_RUNTIME_SWITCH` env 解析，`get_status()` 移除 `runtime_switch_enabled`。模式切换开箱即用、由默认状态决定，AI 可直接修改审核模式；无效模式值仍被拒绝且状态不变（新增 `review_mode_switch_rejected` 审计事件）。测试与文档同步更新。

## [1.0.0] - 2026-08-09（正式发布）

> 本版本为 **1.0.0 正式版**，取代原 `Ver.1.0.0 Demo` 标记。参考仓库 `albertm88/mcp-ssh` 的 `Ver.1.0.0`/`Ver.0.0.1` 指向同一 commit `0e149a9`，属 demo 标记而非发布证据；本次在 `0e149a9` 基线之上完成全部交付能力并经开发者验收，正式发布 1.0.0。
> 发布证据：`docs/release-evidence-1.0.0.md` 与 `docs/release-checklist.md`。

### Added

- 严格 host-key 身份校验（`host_keys.py` + `RejectPolicy`，默认拒绝未知指纹）。
- 统一 1.0 结果 envelope 与稳定错误码（`results.py`）。
- SFTP 原子传输（临时文件 + 字节/SHA-256 校验 + 原子替换 + 失败清理）。
- 目录有界递归与资源限制（文件数/字节/深度/扫描地址，`off` 模式不可关闭）。
- 交付契约测试（`tests/test_delivery_contract.py`）、fake SFTP 控制测试（`tests/test_sftp_control.py`）、行为边界钩子测试（`tests/test_boundary.py`）。
- 行为边界钩子 `_tool_boundary`：14 个工具统一兜底未捕获异常 → 稳定错误码 envelope。
- 发布运维证据：干净构建、升级/回滚演练、pip-audit 无已知漏洞、Windows×WSL2 + Linux(WSL2)×Linux 双平台运行时回归。

### Changed (破坏性，故版本 0.2.0 → 1.0.0)

- 所有 MCP 工具返回统一 envelope dict（FastMCP 渲染为结构化 JSON），不再返回纯文本；`text` 字段保留人类可读展示。自动化调用方必须改用 `status`/`error.code`/`error.retryable` 判断。
- 未知主机密钥默认拒绝：未预置 known_hosts 的环境连接将失败并返回 `HOST_KEY_MISMATCH`。首次信任需在 SSH 配置层显式完成（`ssh-keyscan -H` 或 `StrictHostKeyChecking=accept-new`）。
- 批处理 `stop_on_error` 改用结构化状态判断，不再依赖展示文本首行。
- 远端命令非零退出码现在返回 `failed` + `REMOTE_EXIT_NONZERO` envelope，不再报告为成功。
- **平台边界**：明确支持 Windows 与 Linux（含 WSL2）；**macOS 声明为不支持平台**，相关 CI/矩阵条目不适用。

### Fixed

- `ssh_exec` 连接超时/认证失败/网络错误映射为稳定错误码（`CONNECT_TIMEOUT`/`AUTH_FAILED`/`CONNECTION_LOST`），不再裸异常逃逸。
- 四个 SFTP 工具的 host-key/连接失败返回 `HOST_KEY_MISMATCH`/`CONNECT_TIMEOUT` envelope。
- `ssh_download`/`ssh_download_dir` 成功返回真实 `sha256`。
- 批处理失败时 `ok`/`status`/`error` 一致（失败不再 `ok:true`）。
- 输出配额（1 MiB）在 `_read_channel` 实际执行，超限返回 `OUTPUT_LIMIT`。
- 远端路径拒绝 `.` / `..` 组件，堵住敏感路径正则绕过。
- 批处理与 `ssh_mkdir` envelope 携带 `review` 决策绑定（含 `plan_id`）。
- SHA-256 改为流式分块计算，峰值内存 O(chunk) 而非 O(file)。
- 身份文件缺失返回 `INVALID_ARGUMENT`（不再裸 `FileNotFoundError`）。
- 日志对 `export K=value` 的值脱敏为 `***`（`ssh_exec_done`/`unknown_shell`/`windows_cmd_detected`）。
- 依赖约束 `mcp>=1.2.0,<2.0`（mcp 2.0.0 移除 `mcp.server.fastmcp`，干净安装验证时发现）。

### Runtime Evidence（2026-08-09）

- Windows 本地 × WSL2 远端端到端回归通过：hostname、单文件/目录 SFTP roundtrip（SHA-256 一致）、`sleep 3 timeout=1` 超时失败关闭。
- **Linux 本地端（WSL2 Ubuntu, Python 3.14.4）全量通过**：`pytest` 92 passed、真实 E2E（hostname/SFTP/超时）、故障注入（`AUTH_FAILED`/`CONNECT_TIMEOUT`/`INVALID_ARGUMENT`）与 Windows 一致。
- 运行时故障注入：错误密码 `AUTH_FAILED`、不可达端口 `CONNECT_TIMEOUT`、错误指纹/无可信来源 `HOST_KEY_MISMATCH`。
- Windows 干净 venv 安装 wheel + 真实调用 + 卸载回滚演练通过；Linux `pip install --target` 安装 + 真实调用通过。
- `uvx pip-audit` 无已知漏洞。
- **行为边界钩子（`_tool_boundary`）**：14 个工具统一经钩子处理未捕获异常 → 稳定错误码 envelope，保证 100% 返回 envelope；MCP schema 实测完整（`ssh_exec` 6 参数）；钩子专项测试 11 项。
- **重写回归**：server.py 因 PowerShell 编码事故破坏后完整重写（UTF-8 干净，0 损坏字符），重写后 103 测试全过 + WSL2 真实调用正常（hostname/SFTP roundtrip/超时/批处理部分失败）。
- **干净 checkout 构建**：源码复制到临时目录独立 `uv build` 成功（wheel + sdist），独立 `pytest` 103 passed。
- **升级演练**：1.0.0 干净安装后既有 `~/.ssh/config` 直接兼容（`ssh-mcp-wsl-test` 免改配置即用），envelope 契约正常。
- **shell 全量**：sh/bash/自动模式 WSL2 实测成功；zsh 需远端预装（WSL2 未装，`REMOTE_EXIT_NONZERO` 属环境限制）。
- **并发压测**：≤5 并发 WSL2 实测稳定（5/5 成功）；更高并发受远端 sshd `MaxStartups 10:30:100` 限流（真实远端配置边界，非客户端缺陷）。
- 完整证据见 `docs/release-evidence-1.0.0.md`。

### 1.0.0 发布声明（2026-08-09）

- 历史 `Ver.1.0.0`/`Ver.0.0.1` Git 标签指向同一 commit `0e149a9`，属 demo 标记；现已在 `0e149a9` 基线之上完成交付能力并经开发者验收，发布 **1.0.0 正式版**（`pyproject.toml` 版本 `1.0.0`）。
- 破坏性变更（envelope 返回、严格 host-key、批处理结构化判断、非零退出失败）已在上文 **Changed** 节完整声明。
- 已知限制（开发者已接受，见 `docs/release-checklist.md` 标注）：macOS 为不支持平台；12 CI 组合未配置；真实断流注入与恢复演练未执行；ADD 审计（`record_dev_operation`/`query_audit_logs`）因环境无 MCP 降级未落库。

## [0.2.0] - Current development baseline

- SSH command execution, discovery, file operations and four review modes are present in the development baseline.
- Production support and 1.0.0 compatibility guarantees have not yet been declared.
