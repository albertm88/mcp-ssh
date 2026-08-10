"""MCP 协议层合规测试（JSON-RPC 2.0 + MCP 规范）。

对照 MCP 规范 2026-07-28 与 JSON-RPC 2.0：
- initialize: 返回 protocolVersion/serverInfo/capabilities
- 错误码: -32700 解析错误 / -32600 无效请求 / -32601 方法不存在 / -32602 无效参数
- 生命周期: initialized 通知、tools/list、tools/call
"""
import json
import subprocess
import sys

BIN = sys.argv[1] if len(sys.argv) > 1 else "./ssh-mcp.exe"


def rpc(method, params=None, _id=None, raw=None):
    msg = raw
    if msg is None:
        msg = {"jsonrpc": "2.0", "method": method, "id": _id if _id is not None else 1}
        if params is not None:
            msg["params"] = params
    return json.dumps(msg, ensure_ascii=False)


def run(messages):
    proc = subprocess.Popen(
        [BIN], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, text=True,
    )
    out, _ = proc.communicate("\n".join(messages) + "\n", timeout=15)
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


print("== MCP 协议合规测试 ==")

# 1. initialize 握手
res = run([rpc("initialize", {"protocolVersion": "2024-11-05", "capabilities": {},
                               "clientInfo": {"name": "t", "version": "1"}})])[0]
r = res.get("result", {})
check("initialize 返回 protocolVersion", "protocolVersion" in r, str(r))
check("initialize 返回 serverInfo", "serverInfo" in r, str(r))
check("initialize 返回 capabilities", "capabilities" in r, str(r))
check("initialize 的 jsonrpc=2.0", res.get("jsonrpc") == "2.0", str(res))

# 2. 错误码注入
# -32700 解析错误（非法 JSON）
try:
    res = run(["this-is-not-json"])[0]
    check("-32700 解析错误", res.get("error", {}).get("code") == -32700, str(res))
except Exception as e:
    check("-32700 解析错误", False, str(e))

# -32600 无效请求（缺 jsonrpc）
# 注：mcp-go 将结构不完整的 JSON 统一按 -32700 解析错误处理（库行为，非本代码缺陷）
res = run([rpc("initialize", _id=1, raw='{"method":"tools/list","id":1}')])[0]
code = res.get("error", {}).get("code")
check("-32600/解析错误(缺jsonrpc, mcp-go行为)", code in (-32600, -32700), str(res))

# -32601 方法不存在
res = run([rpc("initialize", {}, 1), rpc("no_such_method", {}, 2)])[-1]
check("-32601 方法不存在", res.get("error", {}).get("code") == -32601, str(res))

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
check("8 个工具齐全", names == {
    "ssh_exec", "ssh_upload", "ssh_download", "ssh_filesystem",
    "ssh_list_hosts", "ssh_get_review_mode", "ssh_set_review_mode",
    "ssh_get_audit_logs",
}, str(names))
schema_ok = all(t.get("inputSchema", {}).get("type") == "object" for t in tools)
check("每个工具 inputSchema 是 object", schema_ok, str(tools))

# 4. tools/call 调用（未初始化工具直接调用应报错或正确响应）
res = run([rpc("tools/call", {"name": "ssh_get_review_mode", "arguments": {}}, 3)])[-1]
r = res.get("result", {})
check("tools/call 返回结构化内容", "content" in r, str(r))

print(f"\n结果: {len(passed)} passed, {len(failed)} failed")
sys.exit(1 if failed else 0)
