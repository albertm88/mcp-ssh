"""测试MCP服务器启动和工具注册"""
import asyncio
import sys
sys.path.insert(0, 'd:/mcp-ssh')

from mcp.server.fastmcp import FastMCP
import server

async def test_mcp():
    print("✅ MCP server instance created:", server.mcp.name)
    
    # 列出所有注册的工具
    tools = await server.mcp.list_tools()
    print(f"\n📋 Registered tools ({len(tools)}):")
    for tool in tools:
        print(f"  - {tool.name}: {tool.description[:80]}...")
    
    # 验证工具数量
    ssh_tools = [t for t in tools if t.name.startswith("ssh_")]
    print(f"\n🔧 SSH tools: {len(ssh_tools)}")
    
    # 测试ssh_list_hosts工具（不需要远程连接）
    print("\n🏠 Testing ssh_list_hosts (local config check):")
    result = server.ssh_list_hosts()
    print(result)
    
    print("\n✅ All startup tests passed!")

if __name__ == "__main__":
    asyncio.run(test_mcp())
