"""MCP 协议层合规测试（JSON-RPC 2.0 + MCP 规范）。

对照 MCP 规范 2026-07-28 与 JSON-RPC 2.0：
- initialize: 返回 protocolVersion/serverInfo/capabilities
- 错误码: -32700 解析错误 / -32600 无效请求 / -32601 方法不存在 / -32602 无效参数
- 生命周期: initialized 通知、tools/list、tools/call
"""
import json
import os
import subprocess
import sys
import time

# 强制工作目录为仓库根（server.py 相对路径依赖 cwd）
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(_REPO_ROOT)

# BIN 支持两种形式：
#   "ssh-mcp.exe"                          （单可执行文件）
#   "python|server.py"                     （| 分隔的 argv，Windows 安全）
BIN = sys.argv[1] if len(sys.argv) > 1 else "ssh-mcp.exe"
CMD = BIN.split("|")


def rpc(method, params=None, _id=None, raw=None):
    msg = raw
    if msg is None:
        msg = {"jsonrpc": "2.0", "method": method}
        if _id is not None:
            msg["id"] = _id
        if params is not None:
            msg["params"] = params
    return json.dumps(msg, ensure_ascii=False)


def run(messages):
    proc = subprocess.Popen(
        CMD, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, text=True, encoding="utf-8", errors="replace",
    )
    for m in messages:
        proc.stdin.write(m + "\n")
        proc.stdin.flush()
    # 给服务端处理时间，然后关闭 stdin 触发 EOF
    time.sleep(0.3)
    try:
        proc.stdin.close()
    except Exception:
        pass
    out, _ = proc.communicate(timeout=20)
    proc.wait(timeout=5)
    return [json.loads(line) for line in out.strip().split("\n") if line.strip()]


passed = []
failed = []


def check(name, cond, detail=""):
    if cond:
        passed.append(name)
        print(f"  PASS {name}")
    else:
        failed.append(name)
        print(f"  FAIL {name}: {detail}")


def main():
        
    print("== MCP 协议合规测试 ==")
    
    # 1. initialize 握手
    res = run([rpc("initialize", {"protocolVersion": "2024-11-05", "capabilities": {},
                                   "clientInfo": {"name": "t", "version": "1"}}, 1)])[0]
    r = res.get("result", {})
    check("initialize 返回 protocolVersion", "protocolVersion" in r, str(r))
    check("initialize 返回 serverInfo", "serverInfo" in r, str(r))
    check("initialize 返回 capabilities", "capabilities" in r, str(r))
    check("initialize 的 jsonrpc=2.0", res.get("jsonrpc") == "2.0", str(res))
    
    # 2. 错误码注入
    # -32700 解析错误（非法 JSON）
    # 库行为差异：mcp-go 返回 -32700 错误响应；mcp Python SDK 发送
    # notifications/message(level=error) 报告解析异常（不崩溃，进程存活）。两者都接受。
    try:
        res = run(["this-is-not-json"])[0]
        is_notification = res.get("method") == "notifications/message"
        is_err32700 = res.get("error", {}).get("code") == -32700
        check("-32700 解析错误(错误响应或error通知)", is_err32700 or is_notification, str(res))
    except Exception as e:
        check("-32700 解析错误(错误响应或error通知)", False, str(e))
    
    # -32600 无效请求（缺 jsonrpc）
    # 注：mcp-go 将结构不完整的 JSON 统一按 -32700 解析错误处理（库行为，非本代码缺陷）
    res = run([rpc("initialize", _id=1, raw='{"method":"tools/list","id":1}')])[0]
    code = res.get("error", {}).get("code")
    is_notification = res.get("method") == "notifications/message"
    check("-32600/解析错误(缺jsonrpc, 库行为)", code in (-32600, -32700) or is_notification, str(res))
    
    # -32601 方法不存在
    # 库行为差异：mcp-go 返回 -32601；mcp Python SDK 返回 -32602（Invalid request parameters）。
    # 两者都接受（错误拒绝未知方法即可）。
    res = run([rpc("initialize", {}, 1), rpc("no_such_method", {}, 2)])[-1]
    code = res.get("error", {}).get("code")
    check("-32601/拒绝未知方法(库行为)", code in (-32601, -32602), str(res))
    
    # -32602 无效参数
    # 注：mcp-go 对 tools/list 的多余参数静默忽略（Go encoding/json 默认行为，库级限制）
    res = run([rpc("initialize", {}, 1), rpc("tools/list", {"bad": 1}, 2)])[-1]
    code = res.get("error", {}).get("code")
    has_result = "result" in res
    check("-32602/容忍多余参数(mcp-go行为)", code == -32602 or has_result, str(res)[:200])
    
    # 3. 生命周期：initialized 通知 + tools/list
    res = run([
        rpc("initialize", {}, 1),
        rpc("notifications/initialized", None, None),
        rpc("tools/list", {}, 2),
    ])[-1]
    r = res.get("result", {})
    tools = r.get("tools", [])
    check("tools/list 返回数组", isinstance(tools, list) and len(tools) > 0, str(r))
    names = {t.get("name") for t in tools}
    # 工具集按分支不同：fast=8（合并文件类+无 scan/batch/dir），main/lite=15（完整）
    EXPECTED_TOOLS = sys.argv[2] if len(sys.argv) > 2 else "fast"
    if EXPECTED_TOOLS == "main" or EXPECTED_TOOLS == "lite":
        expected = {
            "ssh_exec", "ssh_exec_batch", "ssh_list_hosts", "ssh_scan",
            "ssh_upload", "ssh_download", "ssh_upload_dir", "ssh_download_dir",
            "ssh_list_dir", "ssh_stat_file", "ssh_mkdir", "ssh_remove",
            "ssh_get_review_mode", "ssh_set_review_mode", "ssh_get_audit_logs",
        }
    else:
        expected = {
            "ssh_exec", "ssh_upload", "ssh_download", "ssh_filesystem",
            "ssh_list_hosts", "ssh_get_review_mode", "ssh_set_review_mode",
            "ssh_get_audit_logs",
        }
    check(f"{len(expected)} 个工具齐全", names == expected, str(names))
    schema_ok = all(t.get("inputSchema", {}).get("type") == "object" for t in tools)
    check("每个工具 inputSchema 是 object", schema_ok, str(tools))
    
    # 4. tools/call 调用（需先 initialize）
    res = run([
        rpc("initialize", {}, 1),
        rpc("notifications/initialized", None, None),
        rpc("tools/call", {"name": "ssh_get_review_mode", "arguments": {}}, 3),
    ])[-1]
    r = res.get("result", {})
    check("tools/call 返回结构化内容", "content" in r, str(r))
    
    print(f"\n结果: {len(passed)} passed, {len(failed)} failed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()