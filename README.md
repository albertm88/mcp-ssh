# mcp-ssh (fast)

**Go 实现的 SSH MCP 服务器** — 单二进制、毫秒级启动，让 AI 助手安全地管理远程服务器。

[![Go](https://img.shields.io/badge/Go-1.26+-blue.svg)](https://go.dev/)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![MCP](https://img.shields.io/badge/MCP-1.2.0+-purple.svg)](https://modelcontextprotocol.io/)

> **📦 当前文档为 `fast` 分支（Go 版）**
>
> | 分支 | 实现 | 工具数 | 定位 |
> |------|------|--------|------|
> | **fast（当前）** | **Go 1.26** | 8 | **极速**：单二进制 ~10MB、启动 ~48ms、零环境依赖 |
> | lite | Python | 11 | 简化版 |
> | main | Python | 15 | 完整版 |

- **版本**：1.0.0-fast（2026-08-10）
- **平台**：Windows、Linux（含 WSL2）。macOS 不支持
- **语言**：[English](README_EN.md) | 简体中文

---

## 版本家族（一主二分支）

本项目维护三个并行版本，共用同一套 envelope 契约、4 模式审核与防御纵深，客户端可无感切换：

| 版本 | 分支 | 实现 | 工具数 | 定位 | 适用场景 |
|------|------|------|:---:|------|---------|
| **完整版** | `main` | Python + Paramiko | 15 | 功能最全 | 需要网络扫描、批量命令、目录传输 |
| **简化版** | `lite` | Python + Paramiko | 11 | 功能裁剪 | 文件操作合并、无需扫描 |
| **极速版** | `fast`（本分支） | **Go 1.26** | 8 | 性能优先 | 单二进制、毫秒启动、零依赖 |

### 功能差异对比

| 能力 | main | lite | fast |
|------|:---:|:---:|:---:|
| `ssh_exec` 命令执行 | ✅ | ✅ | ✅ |
| `ssh_upload` / `ssh_download` | ✅ | ✅ | ✅ |
| `ssh_filesystem`（list/stat/mkdir/remove） | ❌ 4 个独立工具 | ✅ 合并 | ✅ 合并 |
| `ssh_scan`（网络扫描） | ✅ | ❌ | ❌ |
| `ssh_exec_batch`（批量命令） | ✅ | ✅ | ❌ |
| `ssh_upload_dir` / `ssh_download_dir`（目录传输） | ✅ | ✅ | ❌ |
| `ssh_list_hosts` | ✅ | ✅ | ✅ |
| 审核模式（off/whitelist/manual/smart） | ✅ | ✅ | ✅ |
| 防御纵深（注入/危险命令拦截） | ✅ | ✅ | ✅ |
| 严格 host key 策略 | ✅ | ✅ | ✅ |
| envelope 契约兼容 | ✅ | ✅ | ✅ |
| 启动延迟（含握手） | ~1749ms | ~1749ms | **~48ms** |
| 部署体积 | venv 58MB | venv 58MB | **单二进制 10.6MB** |
| 环境依赖 | Python + uv/venv | Python + uv/venv | **零** |

> 选择建议：日常管理服务器选 **main**；追求简洁选 **lite**；对启动速度和部署体积敏感（如 CI、无 Python 环境）选 **fast**。

---

## 为什么用 Go？

| 指标 | fast（Go） | Python 版 |
|------|-----------|-----------|
| 启动（含 MCP 握手） | **~48ms** | ~1749ms |
| 部署体积 | **单二进制 10.6MB** | venv 58MB |
| 环境依赖 | **无**（拷一个文件即用） | Python 3.10+、uv/venv |

MCP stdio 协议每次工具调用都重启进程——Go 的启动速度让每次操作几乎零延迟。

## 快速开始（2 分钟）

### 1. 构建（或直接用发布产物）

```bash
git clone https://github.com/albertm88/mcp-ssh.git
cd mcp-ssh
git checkout fast
go build -o ssh-mcp.exe ./cmd/ssh-mcp
```

### 2. 配置 SSH 连接（`~/.ssh/config`）

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
> 默认拒绝未知主机密钥；未预置指纹的连接会失败返回 `HOST_KEY_MISMATCH`。

### 3. 配置 MCP 客户端

```json
{
  "mcpServers": {
    "ssh": {
      "command": "D:\\path\\to\\ssh-mcp.exe",
      "env": {}
    }
  }
}
```

---

## 工具一览（8 个）

| 类别 | 工具 | 说明 |
|------|------|------|
| 命令执行 | `ssh_exec` | 执行命令（key/密码认证、PTY、超时、环境变量） |
| 文件传输 | `ssh_upload` / `ssh_download` | 单文件传输（原子写 + SHA-256 校验 + 敏感路径守卫） |
| 远端文件 | `ssh_filesystem` | 统一文件系统操作：`list` / `stat` / `mkdir` / `remove` |
| 主机发现 | `ssh_list_hosts` | 列出配置主机 |
| 审核管理 | `ssh_get_review_mode` / `ssh_set_review_mode` | 查看 / 切换审核模式 |
| 审计查询 | `ssh_get_audit_logs` | 查询最近行为日志（只读） |

## 审核机制（4 模式）

| 模式 | 行为 |
|------|------|
| `off` | 直接放行（资源限制与防御纵深仍生效） |
| `whitelist` | 仅允许白名单规则命令（默认模式，失败安全） |
| `manual` | 人工确认（本地终端） |
| `smart` | 黑名单拒绝 → 安全白名单放行 → 降级人工 |

**防御纵深**：命令注入特征与危险命令拦截在**所有模式**生效（含 off），
危险命令仅 `allow_dangerous=True` 豁免，注入特征无豁免。

## 架构

```
┌─────────────────┐     stdio      ┌──────────────────────┐
│   MCP Client    │ ◄────────────► │  ssh-mcp (Go 1.26)   │
│ (Claude/VSCode/ │                │  mcp-go v0.57        │
│  Trae/Qoder/    │                │                      │
│  Codex/Cursor)  │                └──────────┬───────────┘
└─────────────────┘                           │
                              ┌───────────────┼───────────────┐
                              │               │               │
                              ▼               ▼               ▼
                        ┌──────────┐    ┌──────────┐    ┌──────────┐
                        │ SSH Tools│    │  Review  │    │  Audit   │
                        │  (8)     │    │  Engine  │    │          │
                        │          │    │          │    │ JSON-lines│
                        │ ssh_exec │    │ 4 modes  │    │ to disk  │
                        │ ssh_upload│   │          │    │ (脱敏)    │
                        │ ...      │    │ whitelist│    └──────────┘
                        └────┬─────┘    │ manual   │
                             │          │ smart    │
                             │          │ off      │
                             │          └────┬─────┘
                             │               │
                             ▼               ▼
                    ┌──────────────────────────────┐
                    │  x/crypto/ssh + pkg/sftp      │
                    │  (key auth → password fallback│
                    │   strict host-key policy)     │
                    └──────────────────────────────┘
```

## 开发与测试

```bash
go build ./...      # 构建
go vet ./...        # 静态检查
go test ./...       # 单元测试
```

真实 E2E（需 WSL2 或远程主机）：

```bash
SSH_E2E_HOST=myhost go test -run TestE2E -v ./internal/sshclient/
```

## 项目结构

```
├── cmd/ssh-mcp/          # 入口
├── internal/
│   ├── server/           # MCP 工具注册与 handler
│   ├── sshclient/        # 连接/认证/执行/SFTP/host key 策略
│   ├── review/           # 4 模式审核引擎 + 防御纵深
│   ├── results/          # envelope 契约（与 Python 版兼容）
│   └── audit/            # JSONL 审计 + 脱敏
├── .github/workflows/    # Go CI（build/vet/test + 交叉编译）
└── go.mod
```
