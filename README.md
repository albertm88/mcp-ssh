# mcp-ssh

**跨平台 SSH MCP 服务器** — 让 AI 助手安全地管理远程服务器。

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![MCP](https://img.shields.io/badge/MCP-1.2.0+-purple.svg)](https://modelcontextprotocol.io/)

> **📦 当前文档为 `main` 分支（完整版）**
>
> | 版本 | 分支 | 说明 |
> |------|------|------|
> | **main（当前）** | `main` | **完整版**：15 个 MCP 工具（含 `ssh_scan` 网络扫描、独立文件工具），含质量与安全加固 |
> | 简化版 | `lite` | 11 个 MCP 工具，文件类操作合并为 `ssh_filesystem`，移除 `ssh_scan` |

- **版本**：1.0.1（2026-08-10，质量与安全加固）
- **平台**：Windows、Linux（含 WSL2）。macOS 不支持
- **语言**：[English](README_EN.md) | 简体中文

---

## 快速开始（5 分钟）

### 1. 安装依赖

需要 Python 3.10+ 与 [uv](https://docs.astral.sh/uv/)：

```bash
# Windows
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"

# Linux / macOS
curl -LsSf https://astral.sh/uv/install.sh | sh
```

### 2. 获取代码并安装

```bash
git clone https://github.com/albertm88/mcp-ssh.git
cd mcp-ssh
uv sync        # 创建虚拟环境并安装依赖
```

### 3. 配置 SSH 连接（`~/.ssh/config`）

```ssh-config
Host myserver
    HostName 192.168.1.100
    User ubuntu
    IdentityFile ~/.ssh/id_ed25519
```

```bash
ssh myserver "echo ok"          # 先手动验证 SSH 可连
ssh-keyscan -H myserver >> ~/.ssh/known_hosts   # 信任主机密钥（首次必做）
```

> 无密钥时可用密码：设置环境变量 `SSH_PASS_MYSERVER`（别名大写、点/横线转下划线）。
> 本工具默认拒绝未知主机密钥；未预置指纹的连接会失败返回 `HOST_KEY_MISMATCH`。

### 4. 配置 MCP 客户端（通用格式）

所有 MCP 客户端（Claude Desktop、VS Code、Cursor、Trae、Qoder、Codex 等）使用**同一套 JSON 配置**，仅配置文件路径不同：

```json
{
  "mcpServers": {
    "ssh": {
      "command": "uv",
      "args": ["run", "--directory", "/绝对路径/mcp-ssh", "python", "server.py"],
      "env": { "SSH_REVIEW_MODE": "whitelist" }
    }
  }
}
```

把上面这段 JSON 加入你客户端的 MCP 配置文件：

| 客户端 | 配置文件位置 |
|--------|-------------|
| Claude Desktop | `claude_desktop_config.json`（应用设置中打开） |
| VS Code | 工作区 `.vscode/mcp.json` 或用户 `mcp.json` |
| Cursor | `.cursor/mcp.json` |
| Claude Code / Codex CLI | `claude mcp add ssh -- uv run --directory $(pwd) python server.py` |
| 其他 | 在客户端 MCP 设置中添加同名 JSON 块 |

> **Windows 注意**：路径用 `/` 或 `\\`，如 `D:/mcp-ssh`。配置后重启客户端生效。

### 5. 验证安装

```bash
# 一键验证（环境、依赖、SSH 配置、MCP 握手、真实调用）
uv run python scripts/verify-install.py myserver
```

期望输出（全部 PASS）：

```
[1/5] 环境检查        Python / uv
[2/5] 依赖检查        mcp / paramiko / charset_normalizer
[3/5] SSH 配置检查    config 存在、主机别名、known_hosts
[4/5] MCP 协议验证    tools/list → 15 个工具
[5/5] 真实调用验证    ssh_exec(myserver, hostname) → 成功
结果: 12/12 PASS
```

在 AI 客户端中测试：**"请用 ssh_list_hosts 查看配置的主机，然后 ssh_exec 执行 hostname"**

---

## 工具一览（15 个）

| 类别 | 工具 | 说明 |
|------|------|------|
| 命令执行 | `ssh_exec` / `ssh_exec_batch` | 单条 / 批量执行命令 |
| 主机发现 | `ssh_list_hosts` / `ssh_scan` | 列出配置主机 / 扫描网段 |
| 文件传输 | `ssh_upload` / `ssh_download` / `ssh_upload_dir` / `ssh_download_dir` | 单文件 / 目录传输（原子写 + SHA-256 校验） |
| 远端文件 | `ssh_list_dir` / `ssh_stat_file` / `ssh_mkdir` / `ssh_remove` | 目录列表 / 状态 / 创建 / 删除 |
| 审核管理 | `ssh_get_review_mode` / `ssh_set_review_mode` | 查看 / 切换审核模式 |
| 审计查询 | `ssh_get_audit_logs` | 查询最近行为日志（只读） |

所有工具返回统一 envelope（`status` / `error.code` / `data` / `text`），详见 [结果契约](docs/requirements-1.0.md#4-结构化返回结果)。

---

## 安全机制

### 四模式审核（默认 `whitelist`）

| 模式 | 行为 | 适用场景 |
|------|------|---------|
| `off` | 全部放行 | 开发调试 |
| `whitelist` | 仅白名单命令 | **生产（默认）** |
| `manual` | 每条命令人工确认 | 关键服务器 |
| `smart` | 智能判断，不确定转人工 | 日常运维 |

```python
ssh_get_review_mode()             # 查看当前模式
ssh_set_review_mode("smart")      # 切换模式
```

`manual` 模式自动选择确认通道：客户端弹框（支持 elicitation 的 IDE）→ 本地终端 → 无通道时拒绝执行（fail-closed）。

### 其他安全边界

- **严格 host-key**：未知/错误指纹在认证前拒绝（`HOST_KEY_MISMATCH`），不自动接受
- **敏感路径保护**：`/etc/passwd`、`~/.ssh/id_*` 等禁止读写；路径拒绝 `.` / `..` 组件
- **资源限制**：文件大小 / 目录大小 / 深度 / 扫描地址 / 输出配额，`off` 模式也不可关闭
- **凭据脱敏**：密码、私钥、环境变量值不入日志；日志中 `export K=V` 值替换为 `***`
- **危险命令拦截**：`rm -rf /`、`mkfs`、`shutdown` 等需 `allow_dangerous=True`

---

## 架构

```
┌─────────────────┐     stdio      ┌─────────────┐
│   MCP Client    │ ◄────────────► │  mcp-ssh    │
│ (Claude/VSCode/ │                │   Server    │
│  Trae/Qoder/    │                │             │
│  Codex/Cursor)  │                │             │
└─────────────────┘                └──────┬──────┘
                                          │
                    ┌─────────────────────┼─────────────────────┐
                    │                     │                     │
                    ▼                     ▼                     ▼
              ┌──────────┐        ┌──────────┐          ┌──────────┐
              │ SSH Tools│        │  Review  │          │  Logger  │
              │          │        │  Engine  │          │          │
              │ ssh_exec │        │          │          │ JSON-lines│
              │ ssh_scan │        │ 4 modes  │          │ to disk  │
              │ ssh_upload│       │          │          │ (脱敏)    │
              │ ...      │        │ whitelist│          └──────────┘
              └────┬─────┘        │ manual   │
                   │              │ smart    │
                   │              │ off      │
                   │              └────┬─────┘
                   │                   │
                   ▼                   ▼
            ┌─────────────────────────────────┐
            │      Paramiko SSH Client        │
            │  (key auth → password fallback) │
            └─────────────────────────────────┘
```

---

## 环境变量

| 变量 | 默认 | 说明 |
|------|------|------|
| `SSH_REVIEW_MODE` | `whitelist` | 审核模式：off / whitelist / manual / smart |
| `SSH_PASS` / `SSH_PASS_<HOST>` | - | 全局 / 单主机密码 |
| `SSH_KNOWN_HOSTS` | 系统 known_hosts | 自定义可信主机密钥文件 |
| `SSH_REVIEW_WHITELIST_FILE` | `~/.ssh/mcp-ssh-whitelist.conf` | 白名单规则文件 |
| `SSH_REVIEW_MANUAL_CHANNEL` | `auto` | manual 确认通道：elicit / local / auto |
| `SSH_LOG_FILE` / `SSH_LOG_LEVEL` | `~/.ssh/mcp-ssh.log` / INFO | 日志文件与级别 |

---

## 故障排除

| 问题 | 解决 |
|------|------|
| `HOST_KEY_MISMATCH` | 运行 `ssh-keyscan -H <host> >> ~/.ssh/known_hosts` |
| `AUTH_FAILED` | 检查密钥或 `SSH_PASS_<HOST>` 环境变量 |
| `CONNECTION_LOST` / `CONNECT_TIMEOUT` | 先 `ssh <host>` 手动验证可达性 |
| 命令被拒绝 | 切 `smart` 模式或加白名单规则 |
| MCP 客户端无响应 | 手动运行 `uv run python server.py` 检查报错 |

---

## 项目结构

```
mcp-ssh/
├── server.py          # MCP 服务器（15 个工具）
├── review.py          # 四模式审核引擎
├── host_keys.py       # 严格主机密钥校验
├── results.py         # 统一结果 envelope
├── logger.py          # 日志（脱敏）
├── scripts/
│   ├── verify-install.py   # 安装验证脚本（跨平台）
│   └── verify-linux.sh     # Linux 本地端回归脚本
└── tests/             # 单元 / 契约 / 边界测试
```

## 许可证

[GPL v3](LICENSE)
