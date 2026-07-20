# mcp-ssh

**轻量级跨平台 SSH MCP 服务器** — 让 AI 助手安全地管理远程服务器。

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![MCP](https://img.shields.io/badge/MCP-1.2.0+-purple.svg)](https://modelcontextprotocol.io/)

[English](README_EN.md) | 简体中文

---

## 环境搭建（详细步骤）

### 步骤 1：安装 Python 和 uv

**Windows**：
```powershell
# 安装 Python 3.10+（从 python.org 下载，勾选 Add to PATH）
# 安装 uv（Python 包管理器）
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"

# 验证
python --version    # 应显示 3.10.x 或更高
uv --version        # 应显示 0.5.x 或更高
```

**macOS / Linux**：
```bash
# 安装 uv
curl -LsSf https://astral.sh/uv/install.sh | sh

# 验证
python3 --version   # 应显示 3.10.x 或更高
uv --version
```

> **为什么用 uv？** 比 pip 快 10-100 倍，自动创建虚拟环境，避免依赖冲突。

---

### 步骤 2：获取代码

```bash
# 方式一：Git 克隆（推荐）
git clone https://github.com/albertm88/mcp-ssh.git
cd mcp-ssh

# 方式二：下载 ZIP
# 从 GitHub 下载 ZIP 解压后进入目录
```

---

### 步骤 3：安装依赖

```bash
# 使用 uv 自动创建虚拟环境并安装依赖
uv sync

# 验证安装（应显示 mcp-ssh 相关包）
uv pip list | grep -E "mcp|paramiko"
```

**常见问题**：
- `uv: command not found` → 重启终端，或手动添加 uv 到 PATH
- `python not found` → Windows 安装 Python 时勾选 "Add Python to PATH"
- 权限错误 → Linux/macOS 加 `sudo`，或检查目录权限

---

### 步骤 4：配置 SSH 连接

#### 4.1 生成 SSH 密钥（如没有）

```bash
# Linux/macOS
ssh-keygen -t ed25519 -C "your_email@example.com"

# Windows PowerShell
ssh-keygen -t ed25519 -C "your_email@example.com"
# 密钥保存在 C:\Users\<用户名>\.ssh\id_ed25519
```

#### 4.2 配置 SSH 主机（`~/.ssh/config`）

**文件路径**：
- Linux/macOS：`~/.ssh/config`
- Windows：`C:\Users\<用户名>\.ssh\config`

**示例配置**：
```ssh-config
# 主机别名：myserver（可自定义）
Host myserver
    HostName 192.168.1.100      # 服务器 IP 或域名
    User ubuntu                  # SSH 用户名
    Port 22                      # SSH 端口（默认 22）
    IdentityFile ~/.ssh/id_ed25519  # 私钥路径
    ServerAliveInterval 60       # 保持连接（可选）

# 另一台服务器：生产环境
Host prod-web
    HostName 203.0.113.10
    User admin
    Port 2222
    IdentityFile ~/.ssh/id_rsa_prod
```

**验证 SSH 连接**：
```bash
# 测试别名是否生效
ssh myserver "echo 'SSH 连接成功'"

# 如果失败，检查：
# 1. 服务器是否在线：ping 192.168.1.100
# 2. 端口是否开放：telnet 192.168.1.100 22
# 3. 密钥权限：chmod 600 ~/.ssh/id_ed25519（Linux/macOS）
```

#### 4.3 密码认证（备选，不推荐）

如果无法使用密钥，可设置密码环境变量：

```bash
# Linux/macOS（临时）
export SSH_PASS_MYSERVER="your-password"

# Linux/macOS（永久，添加到 ~/.bashrc 或 ~/.zshrc）
echo 'export SSH_PASS_MYSERVER="your-password"' >> ~/.bashrc

# Windows PowerShell（临时）
$env:SSH_PASS_MYSERVER = "your-password"

# Windows（永久，系统环境变量）
# 设置 → 系统 → 关于 → 高级系统设置 → 环境变量 → 新建
# 变量名：SSH_PASS_MYSERVER
# 变量值：your-password
```

> **命名规则**：`SSH_PASS_` + 主机别名（大写，点/横线转下划线）
> - `myserver` → `SSH_PASS_MYSERVER`
> - `prod-web` → `SSH_PASS_PROD_WEB`
> - `192.168.1.100` → `SSH_PASS_192_168_1_100`

---

### 步骤 5：配置 MCP 客户端

#### 5.1 Claude Code（推荐）

```bash
# 在项目目录下执行
claude mcp add ssh -- uv run --directory $(pwd) python server.py

# 验证配置
claude mcp list
# 应显示：ssh: uv run --directory /path/to/mcp-ssh python server.py
```

#### 5.2 VS Code / Cursor

编辑 MCP 配置文件：

**路径**：
- VS Code：`~/.vscode/mcp.json` 或工作区 `.vscode/mcp.json`
- Cursor：`~/.cursor/mcp.json`

**配置内容**：
```json
{
  "mcpServers": {
    "ssh": {
      "command": "uv",
      "args": [
        "run",
        "--directory",
        "/absolute/path/to/mcp-ssh",
        "python",
        "server.py"
      ],
      "env": {
        "SSH_REVIEW_MODE": "whitelist"
      }
    }
  }
}
```

> **注意**：Windows 路径用 `\\` 或 `/`，如 `D:/mcp-ssh` 或 `D:\\mcp-ssh`

#### 5.3 Trae / Qoder / Codex

这些客户端通常自动发现 MCP 配置，或参考各自的 MCP 设置文档。

**通用原则**：
1. 找到客户端的 MCP 配置文件（通常是 JSON）
2. 添加 `ssh` 服务器配置（同 VS Code 格式）
3. 重启客户端生效

---

### 步骤 6：验证安装

#### 6.1 测试 MCP 服务器

```bash
# 直接运行服务器（应显示 MCP 协议握手信息）
uv run python server.py

# 按 Ctrl+C 退出
```

#### 6.2 在 AI 客户端中测试

**Claude Code**：
```
请使用 ssh_list_hosts 查看配置的主机
```

**预期返回**：
```
配置的主机别名：
  myserver → ubuntu@192.168.1.100:22
  prod-web → admin@203.0.113.10:2222
```

**如果失败**：
1. 检查 MCP 配置路径是否正确
2. 检查 `uv` 是否在 PATH 中
3. 查看客户端日志（Claude Code：`claude --debug`）

---

### 步骤 7：首次使用建议

```bash
# 1. 先测试简单命令（whitelist 模式默认允许）
ssh_exec("myserver", "whoami")
ssh_exec("myserver", "df -h")

# 2. 测试文件上传（创建一个测试文件）
echo "test" > test.txt
ssh_upload("myserver", "test.txt", "/tmp/test.txt")

# 3. 测试审核模式切换
ssh_set_review_mode("smart")   # 智能模式
ssh_exec("myserver", "ls -la") # 自动放行
```

---

### 故障排除速查

| 问题 | 原因 | 解决 |
|------|------|------|
| `uv: command not found` | uv 未安装或未在 PATH | 重新安装 uv，重启终端 |
| `python: command not found` | Python 未安装或未在 PATH | 安装 Python 3.10+，勾选 Add to PATH |
| `No module named 'mcp'` | 依赖未安装 | 运行 `uv sync` |
| `Connection refused` | SSH 服务未启动 | 检查远程 `sudo systemctl status ssh` |
| `Permission denied` | 密钥/密码错误 | 检查 `ssh -v myserver` 调试输出 |
| `command not found`（远程） | 远程缺少该命令 | 换用其他命令，或远程安装 |
| 中文乱码 | 编码不匹配 | 已自动处理，如仍有问题检查远程 `locale` |
| MCP 客户端无响应 | 服务器未启动 | 检查客户端日志，手动运行 `uv run python server.py` 测试 |

---

### 下一步

- 阅读 [核心功能](#核心功能) 了解所有工具
- 阅读 [安全机制](#安全机制四模式审核) 配置审核策略
- 查看 [常见问题](#常见问题) 解决使用中的问题

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
              │ ssh_upload│       │          │          │          │
              │ ...      │        │ whitelist│          │          │
              └────┬─────┘        │ manual   │          └──────────┘
                   │              │ smart    │
                   │              │ off      │
                   │              └────┬─────┘
                   │                   │
                   ▼                   ▼
            ┌─────────────────────────────────┐
            │      Paramiko SSH Client        │
            │  (key auth → password fallback) │
            └─────────────────────────────────┘
                           │
                           ▼
                    ┌─────────────┐
                    │   Remote    │
                    │   Servers   │
                    └─────────────┘
```

**数据流**：AI 请求 → MCP 协议 → 审核引擎 → SSH 执行 → 日志记录 → 返回结果

---

## 核心功能

| 功能 | 工具 | 示例 |
|------|------|------|
| **执行命令** | `ssh_exec` | `ssh_exec("myserver", "df -h")` |
| **批量执行** | `ssh_exec_batch` | `ssh_exec_batch("myserver", ["df -h", "free -h"])` |
| **上传文件** | `ssh_upload` | `ssh_upload("myserver", "local.txt", "/remote/")` |
| **下载文件** | `ssh_download` | `ssh_download("myserver", "/remote/log.txt", "local.txt")` |
| **扫描主机** | `ssh_scan` | `ssh_scan("192.168.1.0/24")` |
| **目录操作** | `ssh_list_dir` / `ssh_mkdir` / `ssh_remove` | 管理远程目录 |

> `host` 支持 `~/.ssh/config` 中的别名，或 `user@ip` 格式。

---

## 安全机制（四模式审核）

默认 **whitelist** 模式，只允许安全命令。支持运行时切换：

| 模式 | 行为 | 场景 |
|------|------|------|
| `off` | 全部放行 | 开发调试 |
| `whitelist` | 仅白名单命令 | **生产环境（默认）** |
| `manual` | 每条命令人工确认 | 关键服务器 |
| `smart` | 智能判断，不确定转人工 | 日常运维 |

```python
# 查看当前模式
ssh_get_review_mode()

# 切换模式（无需重启）
ssh_set_review_mode("smart")
```

### 自定义白名单

编辑 `~/.ssh/mcp-ssh-whitelist.conf`（或项目内 `whitelist.conf` 模板）：

```conf
^ls\b                    # 允许 ls
^cat\s+[^|;&]+$         # 允许 cat（禁止管道）
^docker\s+ps\b          # 允许 docker ps
```

---

## 配置

### SSH 主机（`~/.ssh/config`）

```ssh-config
Host myserver
    HostName 192.168.1.100
    User ubuntu
    IdentityFile ~/.ssh/id_ed25519
```

### 密码认证（可选）

```bash
# Linux/macOS
export SSH_PASS_MYSERVER="password"

# Windows PowerShell
$env:SSH_PASS_MYSERVER = "password"
```

### 环境变量

| 变量 | 默认 | 说明 |
|------|------|------|
| `SSH_PASS` | - | 全局密码 |
| `SSH_PASS_<HOST>` | - | 单主机密码 |
| `SSH_REVIEW_MODE` | `whitelist` | 审核模式 |
| `SSH_REVIEW_WHITELIST_FILE` | `~/.ssh/mcp-ssh-whitelist.conf` | 白名单文件 |
| `SSH_LOG_LEVEL` | `INFO` | 日志级别 |

---

## 常见问题

**Q: 命令被拒绝了？**  
A: 默认 whitelist 模式。用 `ssh_set_review_mode("smart")` 切换，或添加白名单规则。

**Q: 中文乱码？**  
A: 已自动处理 UTF-8/GBK/GB2312/Big5。如仍有问题，检查远程 `locale` 设置。

**Q: 连接失败？**  
A: 先 `ssh user@host` 手动测试。或检查 `~/.ssh/config` 格式、密码环境变量名（点/横线转下划线，大写）。

**Q: 如何执行危险命令（如 rm -rf）？**  
A: `ssh_exec(host, "rm -rf /tmp/test", allow_dangerous=True)`。或切换 `off` 模式。

---

## 项目结构

```
mcp-ssh/
├── server.py          # MCP 服务器（工具定义）
├── review.py          # 审核引擎（四模式）
├── logger.py          # 日志模块
├── whitelist.conf     # 白名单规则模板
└── pyproject.toml     # 依赖配置
```

---

## 许可证

[GPL v3](LICENSE)
