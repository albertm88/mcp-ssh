# mcp-ssh (fast)

**SSH MCP server in Go** — single binary, millisecond startup, lets AI assistants safely manage remote servers.

[![Go](https://img.shields.io/badge/Go-1.26+-blue.svg)](https://go.dev/)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![MCP](https://img.shields.io/badge/MCP-1.2.0+-purple.svg)](https://modelcontextprotocol.io/)

> **📦 This document is for the `fast` branch (Go edition)**
>
> | Branch | Implementation | Tools | Positioning |
> |--------|----------------|-------|-------------|
> | **fast (current)** | **Go 1.26** | 8 | **Fastest**: single binary ~10MB, ~48ms startup, zero env deps |
> | lite | Python | 11 | Simplified edition |
> | main | Python | 15 | Full edition |

- **Version**: 1.0.0-fast (2026-08-10)
- **Platforms**: Windows, Linux (incl. WSL2). macOS is **not** supported
- **Language**: English | [简体中文](README.md)

---

## Why Go?

| Metric | fast (Go) | Python edition |
|--------|-----------|----------------|
| Startup (incl. MCP handshake) | **~48ms** | ~1749ms |
| Deployment size | **Single binary 10.6MB** | venv 58MB |
| Environment deps | **None** (copy one file) | Python 3.10+, uv/venv |

MCP stdio restarts the process per tool call — Go's startup speed makes each call nearly zero-latency.

## Quick Start (2 minutes)

### 1. Build (or use release artifacts)

```bash
git clone https://github.com/albertm88/mcp-ssh.git
cd mcp-ssh
git checkout fast
go build -o ssh-mcp ./cmd/ssh-mcp
```

### 2. Configure SSH (`~/.ssh/config`)

```ssh-config
Host myserver
    HostName 192.168.1.100
    User ubuntu
    IdentityFile ~/.ssh/id_ed25519
```

```bash
ssh myserver "echo ok"          # verify SSH first
ssh-keyscan -H myserver >> ~/.ssh/known_hosts   # trust host key (required once)
```

> No key? Use password: set env `SSH_PASS_MYSERVER` (alias uppercased, dots/dashes → underscores).
> Unknown host keys are rejected by default (`HOST_KEY_MISMATCH`).

### 3. Configure MCP client

```json
{
  "mcpServers": {
    "ssh": {
      "command": "/path/to/ssh-mcp",
      "env": {}
    }
  }
}
```

---

## Tools (8)

| Category | Tool | Description |
|----------|------|-------------|
| Command | `ssh_exec` | Run command (key/password auth, PTY, timeout, env) |
| Transfer | `ssh_upload` / `ssh_download` | Single-file transfer (atomic + SHA-256 + sensitive guard) |
| Remote FS | `ssh_filesystem` | Unified FS ops: `list` / `stat` / `mkdir` / `remove` |
| Discovery | `ssh_list_hosts` | List configured hosts |
| Review | `ssh_get_review_mode` / `ssh_set_review_mode` | View / switch review mode |
| Audit | `ssh_get_audit_logs` | Query recent behavior logs (read-only) |

## Review modes (4)

| Mode | Behavior |
|------|----------|
| `off` | Allow all (resource limits & defense-in-depth still enforced) |
| `whitelist` | Only whitelist rules (default, fail-safe) |
| `manual` | Human confirmation (local terminal) |
| `smart` | Blacklist deny → safe whitelist allow → manual fallback |

**Defense-in-depth**: injection patterns & dangerous commands enforced in **all modes** (incl. off);
dangerous exempt only with `allow_dangerous=True`; injection never exempt.

## Development & testing

```bash
go build ./...      # build
go vet ./...        # static check
go test ./...       # unit tests
```

Real E2E (needs WSL2 or remote host):

```bash
SSH_E2E_HOST=myhost go test -run TestE2E -v ./internal/sshclient/
```

## Project layout

```
├── cmd/ssh-mcp/          # entrypoint
├── internal/
│   ├── server/           # MCP tool registration & handlers
│   ├── sshclient/        # connect/auth/exec/SFTP/host-key policy
│   ├── review/           # 4-mode review engine + defense-in-depth
│   ├── results/          # envelope contract (Python-compatible)
│   └── audit/            # JSONL audit + redaction
├── .github/workflows/    # Go CI (build/vet/test + cross-compile)
└── go.mod
```
