// ssh-mcp fast 版入口：跨平台 SSH MCP 服务器（Go 实现）。
package main

import (
	"fmt"
	"os"

	mcpserver "github.com/mark3labs/mcp-go/server"

	"github.com/albertm88/mcp-ssh/internal/server"
)

func main() {
	if err := mcpserver.ServeStdio(server.Register()); err != nil {
		fmt.Fprintf(os.Stderr, "ssh-mcp 启动失败：%v\n", err)
		os.Exit(1)
	}
}
