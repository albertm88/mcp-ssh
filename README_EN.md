# mcp-ssh

**Lightweight Cross-Platform SSH MCP Server** — Let AI assistants securely manage remote servers.

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![MCP](https://img.shields.io/badge/MCP-1.2.0+-purple.svg)](https://modelcontextprotocol.io/)

[English](README_EN.md) | [简体中文](README.md)

---

## Setup Guide (Step by Step)

### Step 1: Install Python and uv

**Windows**:
```powershell
# Install Python 3.10+ (download from python.org, check "Add to PATH")
# Install uv (Python package manager)
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"

# Verify
python --version    # Should show 3.10.x or higher
uv --version        # Should show 0.5.x or higher
```

**macOS / Linux**:
```bash
# Install uv
curl -LsSf https://astral.sh/uv/install.sh | sh

# Verify
python3 --version   # Should show 3.10.x or higher
uv --version
```

> **Why uv?** 10-100x faster than pip, auto-creates virtualenv, avoids dependency conflicts.

---

### Step 2: Get the Code

```bash
# Option 1: Git clone (recommended)
git clone https://github.com/albertm88/mcp-ssh.git
cd mcp-ssh

# Option 2: Download ZIP
# Download ZIP from GitHub, extract and enter directory
```

---

### Step 3: Install Dependencies

```bash
# Use uv to auto-create virtualenv and install dependencies
uv sync

# Verify installation (should show mcp-ssh related packages)
uv pip list | grep -E "mcp|paramiko"
```

**Common Issues**:
- `uv: command not found` → Restart terminal, or manually add uv to PATH
- `python not found` → When installing Python on Windows, check "Add Python to PATH"
- Permission errors → Add `sudo` on Linux/macOS, or check directory permissions

---

### Step 4: Configure SSH Connection

#### 4.1 Generate SSH Key (if none)

```bash
# Linux/macOS
ssh-keygen -t ed25519 -C "your_email@example.com"

# Windows PowerShell
ssh-keygen -t ed25519 -C "your_email@example.com"
# Key saved to C:\Users\<username>\.ssh\id_ed25519
```

#### 4.2 Configure SSH Hosts (`~/.ssh/config`)

**File path**:
- Linux/macOS: `~/.ssh/config`
- Windows: `C:\Users\<username>\.ssh\config`

**Example configuration**:
```ssh-config
# Host alias: myserver (customizable)
Host myserver
    HostName 192.168.1.100      # Server IP or domain
    User ubuntu                  # SSH username
    Port 22                      # SSH port (default 22)
    IdentityFile ~/.ssh/id_ed25519  # Private key path
    ServerAliveInterval 60       # Keep-alive (optional)

# Another server: production
Host prod-web
    HostName 203.0.113.10
    User admin
    Port 2222
    IdentityFile ~/.ssh/id_rsa_prod
```

**Verify SSH connection**:
```bash
# Test if alias works
ssh myserver "echo 'SSH connection successful'"

# If fails, check:
# 1. Server is online: ping 192.168.1.100
# 2. Port is open: telnet 192.168.1.100 22
# 3. Key permissions: chmod 600 ~/.ssh/id_ed25519 (Linux/macOS)
```

#### 4.3 Password Authentication (Fallback, Not Recommended)

If key auth is unavailable, set password environment variables:

```bash
# Linux/macOS (temporary)
export SSH_PASS_MYSERVER="your-password"

# Linux/macOS (permanent, add to ~/.bashrc or ~/.zshrc)
echo 'export SSH_PASS_MYSERVER="your-password"' >> ~/.bashrc

# Windows PowerShell (temporary)
$env:SSH_PASS_MYSERVER = "your-password"

# Windows (permanent, system environment variables)
# Settings → System → About → Advanced system settings → Environment Variables → New
# Variable name: SSH_PASS_MYSERVER
# Variable value: your-password
```

> **Naming rule**: `SSH_PASS_` + host alias (uppercase, dots/hyphens to underscores)
> - `myserver` → `SSH_PASS_MYSERVER`
> - `prod-web` → `SSH_PASS_PROD_WEB`
> - `192.168.1.100` → `SSH_PASS_192_168_1_100`

---

### Step 5: Configure MCP Client

#### 5.1 Claude Code (Recommended)

```bash
# Run in project directory
claude mcp add ssh -- uv run --directory $(pwd) python server.py

# Verify configuration
claude mcp list
# Should show: ssh: uv run --directory /path/to/mcp-ssh python server.py
```

#### 5.2 VS Code / Cursor

Edit MCP configuration file:

**Path**:
- VS Code: `~/.vscode/mcp.json` or workspace `.vscode/mcp.json`
- Cursor: `~/.cursor/mcp.json`

**Configuration**:
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

> **Note**: On Windows, use `\\` or `/` in paths, e.g., `D:/mcp-ssh` or `D:\\mcp-ssh`

#### 5.3 Trae / Qoder / Codex

These clients usually auto-discover MCP configuration, or refer to their respective MCP setup docs.

**General principle**:
1. Find the client's MCP config file (usually JSON)
2. Add `ssh` server configuration (same format as VS Code)
3. Restart client to apply

---

### Step 6: Verify Installation

#### 6.1 Test MCP Server

```bash
# Run server directly (should show MCP protocol handshake)
uv run python server.py

# Press Ctrl+C to exit
```

#### 6.2 Test in AI Client

**Claude Code**:
```
Please use ssh_list_hosts to view configured hosts
```

**Expected response**:
```
Configured host aliases:
  myserver → ubuntu@192.168.1.100:22
  prod-web → admin@203.0.113.10:2222
```

**If fails**:
1. Check if MCP config path is correct
2. Check if `uv` is in PATH
3. Check client logs (Claude Code: `claude --debug`)

---

### Step 7: First Use Recommendations

```bash
# 1. Test simple commands (whitelist mode allows by default)
ssh_exec("myserver", "whoami")
ssh_exec("myserver", "df -h")

# 2. Test file upload (create a test file)
echo "test" > test.txt
ssh_upload("myserver", "test.txt", "/tmp/test.txt")

# 3. Test review mode switching
ssh_set_review_mode("smart")   # Smart mode
ssh_exec("myserver", "ls -la") # Auto-approved
```

---

### Troubleshooting Quick Reference

| Problem | Cause | Solution |
|---------|-------|----------|
| `uv: command not found` | uv not installed or not in PATH | Reinstall uv, restart terminal |
| `python: command not found` | Python not installed or not in PATH | Install Python 3.10+, check "Add to PATH" |
| `No module named 'mcp'` | Dependencies not installed | Run `uv sync` |
| `Connection refused` | SSH service not running | Check remote `sudo systemctl status ssh` |
| `Permission denied` | Wrong key/password | Debug with `ssh -v myserver` |
| `command not found` (remote) | Remote missing command | Use different command, or install on remote |
| Chinese mojibake | Encoding mismatch | Auto-handled, if persists check remote `locale` |
| MCP client no response | Server not started | Check client logs, manually run `uv run python server.py` |

---

### Next Steps

- Read [Core Features](#core-features) to learn all tools
- Read [Security Mechanism](#security-mechanism-four-mode-review) to configure review policies
- Check [FAQ](#faq) to solve common problems

---

## Architecture

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

**Data flow**: AI request → MCP protocol → Review engine → SSH execution → Log recording → Return result

---

## Core Features

| Feature | Tool | Example |
|---------|------|---------|
| **Execute Command** | `ssh_exec` | `ssh_exec("myserver", "df -h")` |
| **Batch Execute** | `ssh_exec_batch` | `ssh_exec_batch("myserver", ["df -h", "free -h"])` |
| **Upload File** | `ssh_upload` | `ssh_upload("myserver", "local.txt", "/remote/")` |
| **Download File** | `ssh_download` | `ssh_download("myserver", "/remote/log.txt", "local.txt")` |
| **Scan Hosts** | `ssh_scan` | `ssh_scan("192.168.1.0/24")` |
| **Directory Ops** | `ssh_list_dir` / `ssh_mkdir` / `ssh_remove` | Manage remote directories |

> `host` supports aliases from `~/.ssh/config`, or `user@ip` format.

---

## Security Mechanism (Four-Mode Review)

Default **whitelist** mode, only allows safe commands. Supports runtime switching:

| Mode | Behavior | Scenario |
|------|----------|----------|
| `off` | Approve all | Development/debugging |
| `whitelist` | Whitelist only | **Production (default)** |
| `manual` | Manual confirmation per command | Critical servers |
| `smart` | Smart judgment, uncertain→manual | Daily operations |

```python
# View current mode
ssh_get_review_mode()

# Switch mode (no restart needed)
ssh_set_review_mode("smart")
```

### Custom Whitelist

Edit `~/.ssh/mcp-ssh-whitelist.conf` (or project `whitelist.conf` template):

```conf
^ls\b                    # Allow ls
^cat\s+[^|;&]+$         # Allow cat (no pipes)
^docker\s+ps\b          # Allow docker ps
```

---

## Configuration

### SSH Hosts (`~/.ssh/config`)

```ssh-config
Host myserver
    HostName 192.168.1.100
    User ubuntu
    IdentityFile ~/.ssh/id_ed25519
```

### Password Authentication (Optional)

```bash
# Linux/macOS
export SSH_PASS_MYSERVER="password"

# Windows PowerShell
$env:SSH_PASS_MYSERVER = "password"
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SSH_PASS` | - | Global password |
| `SSH_PASS_<HOST>` | - | Per-host password |
| `SSH_REVIEW_MODE` | `whitelist` | Review mode |
| `SSH_REVIEW_WHITELIST_FILE` | `~/.ssh/mcp-ssh-whitelist.conf` | Whitelist file |
| `SSH_LOG_LEVEL` | `INFO` | Log level |

---

## FAQ

**Q: Command rejected?**  
A: Default whitelist mode. Use `ssh_set_review_mode("smart")` to switch, or add whitelist rules.

**Q: Chinese mojibake?**  
A: Auto-handled UTF-8/GBK/GB2312/Big5. If persists, check remote `locale` settings.

**Q: Connection failed?**  
A: First test manually with `ssh user@host`. Check `~/.ssh/config` format, password env var names (dots/hyphens to underscores, uppercase).

**Q: How to execute dangerous commands (e.g., rm -rf)?**  
A: `ssh_exec(host, "rm -rf /tmp/test", allow_dangerous=True)`. Or switch to `off` mode.

---

## Project Structure

```
mcp-ssh/
├── server.py          # MCP server (tool definitions)
├── review.py          # Review engine (four modes)
├── logger.py          # Logging module
├── whitelist.conf     # Whitelist rules template
└── pyproject.toml     # Dependencies
```

---

## License

[GPL v3](LICENSE)
