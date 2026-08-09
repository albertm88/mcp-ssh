#!/usr/bin/env bash
# Linux 本地端回归验证（WSL2 Ubuntu / 任意 Linux）
# 用法: bash scripts/verify-linux.sh [远端host配置名]
# 默认远端为 127.0.0.1:2222（本机 sshd）。可通过环境变量 SSH_TEST_HOST / SSH_TEST_IDENTITY 覆盖。
set -u

HOST="${SSH_TEST_HOST:-linux-local}"
IDENTITY="${SSH_TEST_IDENTITY:-}"
KNOWN_HOSTS="${SSH_KNOWN_HOSTS:-}"
SSH_CONFIG="${SSH_CONFIG_FILE:-/tmp/mcp-ssh-linux-test-config}"

export SSH_REVIEW_MODE="${SSH_REVIEW_MODE:-off}"

echo "== mcp-ssh Linux 本地端回归 =="
echo "host=$HOST python=$(python3 --version 2>&1)"

if ! python3 -c "import server, host_keys, results" 2>/dev/null; then
  echo "依赖缺失，尝试安装: pip install --user --break-system-packages mcp<2.0 paramiko charset-normalizer pytest"
  python3 -m pip install --user --break-system-packages \
    "mcp>=1.2.0,<2.0" "paramiko>=3.4.0" "charset-normalizer>=3.3.0" "pytest>=8.0.0" || exit 1
fi

echo "== 1) 编译 =="
python3 -m compileall -q review.py server.py host_keys.py results.py tests && echo "COMPILE_OK" || exit 1

echo "== 2) 全量测试 =="
python3 -m pytest -q tests/ || exit 1

echo "== 3) 真实 E2E（hostname / SFTP / 超时 / 故障注入）=="
SSH_REVIEW_MODE=off SSH_KNOWN_HOSTS="$KNOWN_HOSTS" python3 - <<'PY'
import os, sys, pathlib, tempfile
sys.path.insert(0, ".")
os.environ["SSH_REVIEW_MODE"] = "off"
if os.environ.get("SSH_KNOWN_HOSTS"):
    os.environ["SSH_KNOWN_HOSTS"] = os.environ["SSH_KNOWN_HOSTS"]

import server, host_keys
host_keys._system_known_hosts_path = lambda: pathlib.Path("/nonexistent/system-keys")

import paramiko
cfg = pathlib.Path(os.environ["SSH_CONFIG_FILE"])
host = os.environ["SSH_TEST_HOST"]
identity = os.environ.get("SSH_TEST_IDENTITY", "")
extra = f"  IdentityFile {identity}\n  IdentitiesOnly yes\n" if identity else ""
cfg.write_text(
    f"Host {host}\n  HostName 127.0.0.1\n  User mcp-test\n  Port 2222\n{extra}",
    encoding="utf-8",
)
orig = server._load_ssh_config
def fake_load():
    c = paramiko.SSHConfig()
    with cfg.open(encoding="utf-8") as f:
        c.parse(f)
    return c
server._load_ssh_config = fake_load

r = server.ssh_exec(host, "hostname", timeout=8)
assert r["status"] == "succeeded" and r["data"]["exit_code"] == 0, f"hostname 失败: {r}"
print("E2E_HOSTNAME OK:", r["data"]["stdout"].strip())

d = pathlib.Path(tempfile.mkdtemp())
src = d / "payload.bin"; src.write_bytes(b"linux-regression-" * 40)
up = server.ssh_upload(host, str(src), "/tmp/linux-payload.bin")
assert up["status"] == "succeeded", f"upload 失败: {up}"
dst = d / "got.bin"
dn = server.ssh_download(host, "/tmp/linux-payload.bin", str(dst))
assert dn["status"] == "succeeded" and dst.read_bytes() == src.read_bytes(), "roundtrip 不一致"
assert up["data"]["sha256"] == dn["data"]["sha256"], "sha256 不一致"
print("E2E_SFTP_ROUNDTRIP OK sha256:", up["data"]["sha256"][:16])

r = server.ssh_exec(host, "sleep 3", timeout=1)
assert r["status"] == "timed_out" and r["error"]["code"] == "EXEC_TIMEOUT", f"超时未失败关闭: {r}"
print("E2E_TIMEOUT_OK")

server._load_ssh_config = orig
print("E2E_ALL_OK")
PY
