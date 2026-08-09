# mcp-ssh 1.0.0 发布证据（2026-08-09）

> **1.0.0 正式版发布证据**。原 `Ver.1.0.0` 为 demo 标记（与 `Ver.0.0.1` 同一 commit `0e149a9`）；本文件记录在 `0e149a9` 基线之上完成的全部交付证据。所有命令与输出均在本文生成日（2026-08-09）实测。
> 注：本文由 `release-evidence-0.3.0.md` 更名而来，内容已更新为 1.0.0。

## 制品与哈希

| 制品 | SHA-256 |
|---|---|
| `dist/mcp_ssh-1.0.0-py3-none-any.whl` | `6C93EA402957D827AB5EBD67A5E48225765560EAB3EFBE62BB2EDFCB9C53C927` |
| `dist/mcp_ssh-1.0.0.tar.gz` | `CDFC25E8A149E50A8007DE2A63AE224F3630B9FFBD26119AFCC015CC2857E13B` |
| `uv.lock`（依赖锁，v1.0.0） | `6FD2E52FDE2E2B74D2A2298870EA9439C62D1EC9D88F67401547995EAD3D302F` |

> 0.3.0 候选阶段历史哈希（备查）：wheel `14B0B6C0…`、sdist `3C237D69…`、uv.lock `E8A23F1D…`。

源码基线 commit：`0e149a918e190ae74b6f90efa84de3eb42a663bc`（参考仓库 demo 标记指向同一 commit）。1.0.0 发布物包含全部未提交交付代码（server.py/host_keys.py/results.py/tests/docs，版本 `1.0.0`）。

## 静态与单元验证

- `python -m compileall -q review.py server.py host_keys.py results.py tests` → exit 0
- `uv run pytest -q` → `103 passed`（双环境）
- MCP stdio handshake + `tools/list` → 14 工具
- `uv build` → wheel + sdist 构建成功

## 运行时回归（Windows 本地 × WSL2 远端 `ssh-mcp-wsl-test`）

| 场景 | 结果 |
|---|---|
| `ssh_exec(hostname)` | `succeeded`, exit 0 |
| 单文件上传/下载 | 上传/下载 SHA-256 一致（`a23a9e46…`） |
| 目录上传/下载（2 文件） | 内容一致 |
| `sleep 3` + `timeout=1` | `timed_out` + `EXEC_TIMEOUT`，1.41s 失败关闭 |
| 无可信 known_hosts | `HOST_KEY_MISMATCH`（认证前拒绝，retryable=False） |
| 错误指纹（隔离） | `HOST_KEY_MISMATCH`（认证前拒绝） |
| 错误密码 | `AUTH_FAILED` |
| 不可达端口 | `CONNECT_TIMEOUT`（retryable=True） |
| 身份文件缺失 | `INVALID_ARGUMENT` |
| 环境变量值入日志 | 无泄漏，`export K=value` 脱敏为 `***` |

## Linux 本地端回归（WSL2 Ubuntu，Python 3.14.4，远端 = 同机 127.0.0.1:2222 sshd）

| 场景 | 结果 |
|---|---|
| `compileall` + `pytest` | `103 passed`（Linux 本地端全量，重写后） |
| `ssh_exec(hostname)` | `succeeded`, exit 0（host-key 严格校验通过） |
| 单文件上传/下载 | 上传/下载 SHA-256 一致（`082c8aa3…`），roundtrip 内容一致 |
| `sleep 3` + `timeout=1` | `timed_out` + `EXEC_TIMEOUT` |
| 错误密码（无密钥） | `AUTH_FAILED` |
| 不可达端口 | `CONNECT_TIMEOUT` |
| 身份文件缺失 | `INVALID_ARGUMENT` |
| review 绑定 | `review.plan_id` 非空 |
| wheel 目标目录安装 | 5 模块导入成功 + 真实调用 `succeeded` |

> 矩阵：Windows 本地 × WSL2 远端 + **Linux 本地（WSL2 Ubuntu）** × Linux 远端（127.0.0.1:2222）均已真实验证。**macOS 为不支持平台**（不纳入矩阵）。

## 安装与回滚

- 干净 venv `pip install mcp_ssh-1.0.0-py3-none-any.whl` → 成功，mcp 解析为 1.29.0（`<2.0` 约束生效）
- 从 site-packages 导入 server/host_keys/results → 成功，真实 WSL2 调用成功
- `pip uninstall mcp-ssh` → `Successfully uninstalled`；外部目录 `PackageNotFoundError` 确认移除
- Linux（WSL2）`pip install --target /tmp/linux-clean` → 5 模块导入 + 真实调用成功

## 依赖与安全扫描

- `uvx pip-audit` → **No known vulnerabilities found**
- 源码扫描：无私钥明文（`BEGIN * PRIVATE KEY` 无命中）、无硬编码 API key/token/secret

## 受控跳过项（1.0.0 发布时开发者已接受）

- macOS 本地端：**声明为不支持平台**（2026-08-09 决策），矩阵条目不适用。
- 12 CI 组合（Windows/Linux × Python 3.10-3.13）：未配置 CI workflow。
- 真实网络断流故障注入：`CONNECTION_LOST`/传输中断已由单元层（钩子 + `test_boundary.py`）与 `EXEC_TIMEOUT` 运行时覆盖；真实断流注入未执行。
- 从 git 提交 checkout 构建、恢复（配置保留）演练、运维监控文档未执行。
- ADD 审计（`record_dev_operation`/`query_audit_logs`）：环境无 MCP，降级未落库。

## 运维演练结果（2026-08-09）

- **升级演练**：1.0.0 干净 venv 安装 → 既有 `~/.ssh/config` 直接兼容（`ssh-mcp-wsl-test` 免改配置即用）→ 真实调用 `succeeded` → envelope schema 1.0 正常。
- **干净 checkout 构建**：源码复制到临时目录独立 `uv build` → wheel + sdist 成功；独立 `pytest` 103 passed。
- **shell 全量**：sh/bash/自动模式 WSL2 实测成功；zsh 需远端预装（WSL2 未装）。
- **并发压测**：≤5 并发 WSL2 稳定（5/5）；受远端 sshd `MaxStartups` 限制，更高并发触发限流。
- **行为边界钩子**：14 工具统一 `_tool_boundary` 钩子，未捕获异常 → 稳定错误码 envelope；MCP schema 完整（`ssh_exec` 6 参数）；钩子专项测试 11 项。
- **server.py 重写**：因编码事故损坏后完整重写（UTF-8 干净、0 损坏字符），重写后 103 测试 + WSL2 真实调用全部通过。
