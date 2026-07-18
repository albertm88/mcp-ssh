"""测试MCP服务器导入和工具列表"""
import sys
sys.path.insert(0, 'd:/mcp-ssh')

import server

print("✅ Server module imported successfully")
print("\n📋 Available SSH tools:")
for name in sorted(dir(server)):
    if name.startswith("ssh_") and callable(getattr(server, name)):
        func = getattr(server, name)
        doc = (func.__doc__ or "").split("\n")[0].strip()
        print(f"  - {name}: {doc}")

print("\n🔧 MCP instance created:", server.mcp.name)
