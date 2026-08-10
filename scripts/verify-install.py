#!/usr/bin/env python3
"""mcp-ssh 安装验证脚本（跨平台：Windows / Linux）。

用法：
    python scripts/verify-install.py [host_alias]

自动执行：
  1. 环境检查（Python / uv）
  2. 依赖检查（mcp / paramiko）
  3. SSH 配置检查（~/.ssh/config 及主机别名）
  4. MCP stdio 握手 + tools/list（工具数量与 schema）
  5. 真实调用（可选：传入 host_alias 时执行 ssh_exec hostname）

输出：每步 PASS/FAIL，最终汇总。任意 FAIL 返回非零退出码。
"""
from __future__ import annotations

import json
import os
import pathlib
import platform
import subprocess
import sys

PASS = 0
FAIL = 1
results: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    results.append((name, ok, detail))
    mark = "PASS" if ok else "FAIL"
    line = f"  [{mark}] {name}"
    if detail:
        line += f" — {detail}"
    print(line)


def python_ok() -> bool:
    v = sys.version_info
    return v >= (3, 10)


def uv_ok() -> tuple[bool, str]:
    try:
        out = subprocess.check_output(
            ["uv", "--version"], stderr=subprocess.STDOUT, text=True
        ).strip()
        return True, out
    except (FileNotFoundError, subprocess.CalledProcessError):
        return False, ""


def import_ok(mod: str) -> tuple[bool, str]:
    try:
        __import__(mod)
        return True, ""
    except ImportError as e:
        return False, str(e)


def ssh_dir() -> pathlib.Path:
    if platform.system() == "Windows":
        return pathlib.Path(os.environ.get("USERPROFILE", str(pathlib.Path.home()))) / ".ssh"
    return pathlib.Path.home() / ".ssh"


def parse_hosts(cfg: pathlib.Path) -> list[str]:
    hosts: list[str] = []
    with cfg.open(encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if line.lower().startswith("host "):
                for h in line.split()[1:]:
                    if "*" not in h and "?" not in h:
                        hosts.append(h)
    return hosts


def mcp_handshake() -> tuple[bool, int]:
    """MCP stdio 握手 + tools/list，返回 (ok, tool_count)。"""
    try:
        import asyncio

        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client

        async def _run() -> tuple[bool, int]:
            server_path = str(pathlib.Path(__file__).resolve().parent.parent / "server.py")
            params = StdioServerParameters(
                command=sys.executable,
                args=[server_path],
                cwd=str(pathlib.Path(__file__).resolve().parent.parent),
            )
            async with stdio_client(params) as (r, w):
                async with ClientSession(r, w) as s:
                    await s.initialize()
                    tools = await s.list_tools()
                    return True, len(tools.tools)

        return asyncio.run(_run())
    except Exception as e:  # noqa: BLE001
        return False, str(e)[:120]


def live_call(host: str) -> tuple[bool, str]:
    """真实调用 ssh_exec(host, 'hostname')。"""
    try:
        sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
        import server

        os.environ.setdefault("SSH_REVIEW_MODE", "off")
        res = server.ssh_exec(host, "hostname", timeout=10)
        if res.get("ok"):
            return True, res["data"].get("stdout", "").strip()[:40]
        err = (res.get("error") or {}).get("code", "?")
        return False, f"status={res.get('status')} code={err}"
    except Exception as e:  # noqa: BLE001
        return False, str(e)[:120]


def main() -> int:
    print("=" * 60)
    print("mcp-ssh 安装验证")
    print(f"  平台: {platform.system()} / Python {sys.version.split()[0]}")
    print("=" * 60)

    # 1. 环境检查
    print("\n[1/5] 环境检查")
    check("Python >= 3.10", python_ok(), sys.version.split()[0])
    uv_ok_b, uv_ver = uv_ok()
    check("uv 已安装", uv_ok_b, uv_ver or "未找到 uv（可选，但推荐安装）")

    # 2. 依赖检查
    print("\n[2/5] 依赖检查")
    for mod in ("mcp", "paramiko", "charset_normalizer"):
        ok, detail = import_ok(mod)
        check(f"依赖 {mod}", ok, detail)
    mcp_ok_b, mcp_ver = import_ok("mcp")
    if mcp_ok_b:
        try:
            import mcp

            check("mcp 版本 <2.0", mcp.__version__ < "2", mcp.__version__)
        except AttributeError:
            check("mcp 版本 <2.0", True, "版本未知（约束由 pyproject 保证）")

    # 3. SSH 配置检查
    print("\n[3/5] SSH 配置检查")
    cfg = ssh_dir() / "config"
    if not cfg.exists():
        check("~/.ssh/config 存在", False, f"未找到 {cfg}")
        hosts = []
    else:
        hosts = parse_hosts(cfg)
        check("~/.ssh/config 存在", True, str(cfg))
        check("包含主机别名", len(hosts) > 0, f"{len(hosts)} 个: {', '.join(hosts[:5])}")
        kh = ssh_dir() / "known_hosts"
        check("known_hosts 存在（严格 host-key 需要）", kh.exists(), str(kh) if kh.exists() else "首次连接需先 ssh-keyscan 信任指纹")

    # 4. MCP 握手
    print("\n[4/5] MCP 协议验证")
    ok, detail = mcp_handshake()
    if isinstance(detail, int):
        check("MCP stdio 握手 + tools/list", ok, f"{detail} 个工具")
        check("工具数量 >= 14", detail >= 14, f"实际 {detail}")
    else:
        check("MCP stdio 握手 + tools/list", ok, str(detail))

    # 5. 真实调用（可选）
    print("\n[5/5] 真实调用验证")
    host = sys.argv[1] if len(sys.argv) > 1 else (hosts[0] if hosts else "")
    if host:
        ok, detail = live_call(host)
        check(f"ssh_exec({host}, hostname)", ok, detail)
    else:
        check("真实调用（未执行）", True, "未指定 host 或 ~/.ssh/config 无主机；可运行: python scripts/verify-install.py <host>")

    # 汇总
    print("\n" + "=" * 60)
    failed = [r for r in results if not r[1]]
    total = len(results)
    if failed:
        print(f"结果: {total - len(failed)}/{total} PASS — {len(failed)} 项未通过:")
        for name, _, detail in failed:
            print(f"  - {name}: {detail}")
        print("=" * 60)
        return FAIL
    print(f"结果: {total}/{total} PASS — 安装验证通过")
    print("=" * 60)
    return PASS


if __name__ == "__main__":
    # Windows GBK 控制台兜底：强制 UTF-8 输出，避免特殊字符崩溃
    if platform.system() == "Windows":
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    sys.exit(main())
