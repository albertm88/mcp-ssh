# mcp-ssh 最佳实践与使用指南

本文件总结了在实际使用 mcp-ssh 过程中遇到的问题与解决方案，帮助后续使用者避免重复踩坑。

## 🚀 快速调用模板

**核心原则：用脚本文件，不要用 PowerShell 内联命令。**

### 推荐调用模式

创建一个本地调用脚本（如 `call_ssh.py`），复用以下模板：

```python
"""mcp-ssh 调用模板。"""
import os
import sys

# 必须在 import server 前设置环境变量
os.environ["SSH_PASS_192_168_43_123"] = "ubuntu"  # 按需替换 IP

sys.path.insert(0, "d:/mcp-ssh")
import server  # noqa: E402

HOST = "ubuntu@192.168.43.123"

# 执行单条命令
print(server.ssh_exec(HOST, "hostname; whoami; uname -a", timeout=15))

# 批量执行
print(server.ssh_exec_batch(HOST, [
    "df -h",
    "free -h",
    "uptime",
], timeout=15))

# 扫描网段
print(server.ssh_scan("192.168.43.0/24", timeout=5.0))
```

### ❌ 错误示范（避免）

```powershell
# PowerShell 内联会因引号嵌套、管道符 |、特殊字符解析失败
d:/mcp-ssh/.venv/Scripts/python.exe -c "import sys; sys.path.insert(0,'d:/mcp-ssh'); import server; print(server.ssh_exec('ubuntu@192.168.43.123', 'grep -E \"dashscope|bailian\" /etc/hosts', timeout=15))"
# ↑ 这会失败：PowerShell 把 | 当管道，\" 解析错乱
```

---

## 🛡️ 问题与克服总结

### 问题 1：PowerShell 转义陷阱

**症状**：命令中含 `|`、`"`、`'` 时，PowerShell 解析失败。

**根因**：PowerShell 终端 + `python -c "..."` 形成双层 shell 解析，引号和管道符冲突。

**解决方案**：
- ✅ 把命令写入 `.py` 脚本文件，用变量存储命令字符串
- ✅ 命令中避免 PowerShell 特殊字符，或用脚本文件完全绕开
- ❌ 避免在 PowerShell 中用 `python -c` 内联多行命令

### 问题 2：远程 zsh 兼容性

**症状**：`echo === CPU ===` 报错 `zsh:1: == not found`。

**根因**：zsh 的 `=cmd` 触发路径扩展，`===` 被当作查找命令 `==`。

**解决方案**：
- ✅ 用 `echo [CPU]` 等不含 `=` 的标记
- ✅ 需要特殊 shell 特性时用 `bash -lc` 包裹命令
- ✅ `ssh_exec` 已内置 `shell` 参数，可指定 `shell="bash"`

### 问题 3：网络环境判断不足

**症状**：`ssh_scan` 默认超时 2s 扫不出主机，反复扫描浪费时间。

**根因**：无线网络延迟可达 500ms-2400ms，2s 超时不足。

**解决方案**：
- ✅ 扫描前先用 ping 评估网络延迟
- ✅ 高延迟网络（>500ms）用 `timeout=5.0` 或更大
- ✅ /24 网段扫描耗时约 `254 × timeout / max_workers` 秒

```python
# 先 ping 评估
server.ssh_exec(HOST, "ping -c 3 192.168.43.1", timeout=10)
# 再据此调整扫描超时
server.ssh_scan("192.168.43.0/24", timeout=5.0)  # 高延迟用 5s
```

### 问题 4：grep 全盘搜索效率低

**症状**：全盘 grep 搜索 3+ 分钟未完成，匹配大量无关的 `.vscode-server` 扩展文件。

**根因**：没有排除缓存、扩展、依赖目录。

**解决方案**：
- ✅ 用 `--exclude-dir` 排除噪音目录
- ✅ 聚焦用户项目目录，不要扫 `/home` 全部
- ✅ 用 `--include` 限定文件类型

```python
# 好的做法：聚焦目标目录 + 排除噪音
server.ssh_exec(HOST,
    "grep -rliE 'dashscope|bailian' "
    "--exclude-dir=.vscode-server --exclude-dir=.cache "
    "--exclude-dir=node_modules --exclude-dir=.git "
    "/home/ubuntu/Downloads 2>/dev/null",
    timeout=30)
```

### 问题 5：没有建立可复用调用模式

**症状**：每次调用都重写 `import sys; sys.path.insert(0,...); import server`。

**解决方案**：
- ✅ 创建一个 `call_ssh.py` 模板脚本，后续直接修改命令部分
- ✅ 环境变量（密码）在脚本顶部统一设置，不依赖 PowerShell `$env:`
- ✅ 复杂任务用 `ssh_exec_batch` 一次执行多条命令

---

## 📋 常见任务速查

### 扫描局域网找 SSH 主机

```python
# 低延迟网络（有线）
server.ssh_scan("192.168.43.0/24", timeout=1.5)

# 高延迟网络（无线）— 先 ping 测延迟
server.ssh_scan("192.168.43.0/24", timeout=5.0)
```

### 搜索远程文件

```python
# 排除噪音目录，聚焦项目目录
server.ssh_exec(HOST,
    "grep -rli 'keyword' "
    "--exclude-dir=.cache --exclude-dir=node_modules "
    "/home/ubuntu/Projects 2>/dev/null",
    timeout=30)

# 按文件类型搜索
server.ssh_exec(HOST,
    "find /home/ubuntu/Projects -name '*.py' -newer /tmp/marker 2>/dev/null",
    timeout=15)
```

### 读取远程配置文件

```python
# 直接 cat 配置文件
server.ssh_exec(HOST, "cat /path/to/config.py", timeout=10)

# 查看环境变量中的 key
server.ssh_exec(HOST, "grep DASHSCOPE ~/.bashrc", timeout=10)
```

### 批量系统巡检

```python
server.ssh_exec_batch(HOST, [
    "hostname; uname -a",
    "df -h",
    "free -h",
    "uptime",
    "docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}'",
], timeout=15)
```

### 文件传输

```python
# 上传
server.ssh_upload(HOST, "C:/local/file.py", "/home/ubuntu/remote/file.py")

# 下载
server.ssh_download(HOST, "/home/ubuntu/remote/log.txt", "C:/local/log.txt")
```

---

## ⚙️ 工具参数速查

| 工具 | 关键参数 | 默认值 | 建议 |
|------|---------|--------|------|
| `ssh_exec` | `timeout` | 30 | 简单命令 15s，长命令 60s+ |
| `ssh_exec` | `shell` | None | 远程是 zsh 时用 `shell="bash"` |
| `ssh_exec` | `allow_dangerous` | False | 执行 rm/mkfs 时需设 True |
| `ssh_scan` | `timeout` | 2.0 | 无线网络建议 5.0+ |
| `ssh_scan` | `max_workers` | 100 | /16 网段建议降到 50 |
| `ssh_scan` | `detail` | True | 获取 SSH banner 识别设备 |

---

## 🔑 认证配置速查

| 场景 | 配置方式 |
|------|---------|
| 密码认证 | `SSH_PASS_<IP>` 环境变量（`.` `-` 转 `_`，全大写） |
| 密钥认证 | `~/.ssh/config` 配置 `IdentityFile` |
| 全局兜底密码 | `SSH_PASS` 环境变量 |
| PowerShell 设置 | `$env:SSH_PASS_192_168_43_123="ubuntu"` |
| 脚本内设置 | `os.environ["SSH_PASS_192_168_43_123"]="ubuntu"` |

---

## 📝 日志与调试

日志文件位置：`~/.ssh/mcp-ssh.log`（JSON-lines 格式）

```python
# 开启 DEBUG 日志（在 import server 前）
os.environ["SSH_LOG_LEVEL"] = "DEBUG"
os.environ["SSH_LOG_FLUSH_INTERVAL"] = "2"  # 测试时缩短刷盘间隔

# 查看本地日志
# Windows: type %USERPROFILE%\.ssh\mcp-ssh.log
# Linux:   cat ~/.ssh/mcp-ssh.log
```

关键日志事件：
- `tcp_probe_timeout` — 主机不可达
- `auth_failed` — 密码错误
- `ssh_exec_done` — 命令执行完成（含耗时）
- `ssh_scan_done` — 扫描完成（含发现数量）
