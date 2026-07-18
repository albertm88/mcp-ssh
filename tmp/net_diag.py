"""网络诊断：ping 主机 + 扫描局域网。"""
import os
import sys

os.environ["SSH_PASS_192_168_43_123"] = "ubuntu"
sys.path.insert(0, "d:/mcp-ssh")
import server  # noqa: E402

# 本地 ping 目标主机（Windows: -n）
print("=" * 60)
print("[1] 本地 ping 192.168.43.123 (Windows)")
print("=" * 60)
import subprocess
r = subprocess.run(["ping", "-n", "4", "192.168.43.123"],
                   capture_output=True, text=True, timeout=30)
print(r.stdout)
print(r.stderr)

# 看本机 IP 网段
print("=" * 60)
print("[2] 本机 IP 配置")
print("=" * 60)
r = subprocess.run(["ipconfig"], capture_output=True, text=True, timeout=10)
print(r.stdout[:3000])
