# mcp-ssh

**Lightweight cross-platform SSH MCP server** — let AI assistants safely manage remote servers.

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![MCP](https://img.shields.io/badge/MCP-1.2.0+-purple.svg)](https://modelcontextprotocol.io/)

> **📦 This document is for the `lite` branch (simplified edition)**
>
> | Edition | Branch | Description |
> |---------|--------|-------------|
> | **lite (current)** | `lite` | **Simplified**: 11 MCP tools, FS ops merged into `ssh_filesystem`, `ssh_scan` removed |
> | Full | `main` | 15 MCP tools (incl. `ssh_scan` subnet scan, separate FS tools) |
>
> For the full edition, switch to the `main` branch and read its README.

- **Version**: 1.0.0-lite (2026-08-10)
- **Platforms**: Windows, Linux (incl. WSL2). macOS is **not** supported
- **Language**: English | [简体中文](README.md)

---

## Quick Start (5 minutes)

### 1. Install dependencies

Requires Python 3.10+ and [uv](https://docs.astral.sh/uv/):

```bash
# Windows
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"

# Linux / macOS
curl -LsSf https://astral.sh/uv/install.sh | sh
```

### 2. Get the code and install

```bash
git clone https://github.com/albertm88/mcp-ssh.git
cd mcp-ssh
uv sync        # create venv and install dependencies
```

### 3. Configure SSH (`~/.ssh/config`)

```ssh-config
Host myserver
    HostName 192.168.1.100
    User ubuntu
    IdentityFile ~/.ssh/id_ed25519
```

```bash
ssh myserver "echo ok"          # verify SSH works first
ssh-keyscan -H myserver >> ~/.ssh/known_hosts   # trust host key (required once)
```

> Password auth: set env `SSH_PASS_MYSERVER` (alias uppercased, dots/dashes → underscores).
> Unknown host keys are **rejected by default**; untrusted hosts fail with `HOST_KEY_MISMATCH`.

### 4. Configure the MCP client (generic format)

All MCP clients (Claude Desktop, VS Code, Cursor, Trae, Qoder, Codex, etc.) use the **same JSON block** — only the config file location differs:

```json
{
  "mcpServers": {
    "ssh": {
      "command": "uv",
      "args": ["run", "--directory", "/absolute/path/mcp-ssh", "python", "server.py"],
      "env": { "SSH_REVIEW_MODE": "whitelist" }
    }
  }
}
```

Add this block to your client's MCP config:

| Client | Config file |
|--------|-------------|
| Claude Desktop | `claude_desktop_config.json` (open from app settings) |
| VS Code | workspace `.vscode/mcp.json` or user `mcp.json` |
| Cursor | `.cursor/mcp.json` |
| Claude Code / Codex CLI | `claude mcp add ssh -- uv run --directory $(pwd) python server.py` |
| Others | Add the same JSON block in the client's MCP settings |

> **Windows note**: use `/` or `\\` in paths, e.g. `D:/mcp-ssh`. Restart the client after configuring.

### 5. Verify installation

```bash
# One-shot verification (env, deps, SSH config, MCP handshake, live call)
uv run python scripts/verify-install.py myserver
```

Expected output (all PASS):

```
[1/5] Environment        Python / uv
[2/5] Dependencies       mcp / paramiko / charset_normalizer
[3/5] SSH config         config exists, host aliases, known_hosts
[4/5] MCP protocol       tools/list → 11 tools
[5/5] Live call          ssh_exec(myserver, hostname) → success
Result: 12/12 PASS
```

Test in your AI client: **"Use ssh_list_hosts to list configured hosts, then ssh_exec hostname"**

---

## Tools (11)

| Category | Tools | Description |
|----------|-------|-------------|
| Command | `ssh_exec` / `ssh_exec_batch` | Run single / batch commands |
| Discovery | `ssh_list_hosts` | List configured hosts |
| Transfer | `ssh_upload` / `ssh_download` / `ssh_upload_dir` / `ssh_download_dir` | File / dir transfer (atomic + SHA-256) |
| Remote FS | `ssh_filesystem` | Unified FS ops: `list` / `stat` / `mkdir` / `remove` (via action) |
| Review | `ssh_get_review_mode` / `ssh_set_review_mode` | View / switch review mode |
| Audit | `ssh_get_audit_logs` | Query recent behavior logs (read-only) |

All tools return a unified envelope (`status` / `error.code` / `data` / `text`). See [result contract](docs/requirements-1.0.md#4-结构化返回结果).

---

## Security

### Four review modes (default `whitelist`)

| Mode | Behavior | Use case |
|------|----------|----------|
| `off` | Allow everything | Development |
| `whitelist` | Only whitelisted commands | **Production (default)** |
| `manual` | Human confirmation per command | Critical servers |
| `smart` | Auto-judge, escalate to human | Daily ops |

```python
ssh_get_review_mode()             # view current mode
ssh_set_review_mode("smart")      # switch mode
```

`manual` mode auto-selects the confirmation channel: client dialog (elicitation-capable IDEs) → local terminal → fail-closed reject.

### Other security boundaries

- **Strict host key**: unknown/mismatched fingerprints rejected before auth (`HOST_KEY_MISMATCH`)
- **Sensitive path guard**: `/etc/passwd`, `~/.ssh/id_*` etc. blocked; `.` / `..` components rejected
- **Resource limits**: file size / dir size / depth / scan / output quotas — enforced even in `off` mode
- **Credential redaction**: passwords, keys, env values never logged; `export K=V` values replaced with `***`
- **Dangerous command guard**: `rm -rf /`, `mkfs`, `shutdown` etc. require `allow_dangerous=True`

---

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SSH_REVIEW_MODE` | `whitelist` | Review mode: off / whitelist / manual / smart |
| `SSH_PASS` / `SSH_PASS_<HOST>` | - | Global / per-host password |
| `SSH_KNOWN_HOSTS` | system known_hosts | Custom trusted host-key file |
| `SSH_REVIEW_WHITELIST_FILE` | `~/.ssh/mcp-ssh-whitelist.conf` | Whitelist rules file |
| `SSH_REVIEW_MANUAL_CHANNEL` | `auto` | Manual channel: elicit / local / auto |
| `SSH_LOG_FILE` / `SSH_LOG_LEVEL` | `~/.ssh/mcp-ssh.log` / INFO | Log file and level |

---

## Troubleshooting

| Issue | Fix |
|-------|-----|
| `HOST_KEY_MISMATCH` | Run `ssh-keyscan -H <host> >> ~/.ssh/known_hosts` |
| `AUTH_FAILED` | Check key or `SSH_PASS_<HOST>` env var |
| `CONNECTION_LOST` / `CONNECT_TIMEOUT` | Verify reachability with `ssh <host>` first |
| Command rejected | Switch to `smart` mode or add whitelist rules |
| MCP client unresponsive | Run `uv run python server.py` manually to see errors |

---

## Project layout

```
mcp-ssh/
├── server.py          # MCP server (11 tools)
├── review.py          # Four-mode review engine
├── host_keys.py       # Strict host-key verification
├── results.py         # Unified result envelope
├── logger.py          # Logging (redacted)
├── scripts/
│   ├── verify-install.py   # Cross-platform install verification
│   └── verify-linux.sh     # Linux local-end regression
└── tests/             # Unit / contract / boundary tests
```

## License

[GPL v3](LICENSE)
