package server

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/albertm88/mcp-ssh/internal/audit"
	"github.com/albertm88/mcp-ssh/internal/results"
	"github.com/albertm88/mcp-ssh/internal/review"
	"github.com/albertm88/mcp-ssh/internal/sshclient"
)

// Tool definitions ------------------------------------------------

func sshExecTool() mcp.Tool {
	return mcp.NewTool("ssh_exec",
		mcp.WithDescription("Execute a shell command on a remote host."),
		mcp.WithString("host", mcp.Required(), mcp.Description("Host (alias or user@host:port)")),
		mcp.WithString("command", mcp.Required(), mcp.Description("Command to execute")),
		mcp.WithNumber("timeout", mcp.Description("Timeout seconds, default 30")),
		mcp.WithString("shell", mcp.Description("Remote shell: bash/sh/zsh/cmd/powershell")),
		mcp.WithBoolean("allow_dangerous", mcp.Description("Allow dangerous commands (rm -rf / etc)")),
	)
}

func sshUploadTool() mcp.Tool {
	return mcp.NewTool("ssh_upload",
		mcp.WithDescription("Upload a local file to a remote host (atomic + SHA-256)."),
		mcp.WithString("host", mcp.Required(), mcp.Description("Host")),
		mcp.WithString("local_path", mcp.Required(), mcp.Description("Local file path")),
		mcp.WithString("remote_path", mcp.Required(), mcp.Description("Remote target path")),
		mcp.WithNumber("timeout", mcp.Description("Timeout seconds, default 60")),
		mcp.WithBoolean("overwrite", mcp.Description("Allow overwrite, default false")),
	)
}

func sshDownloadTool() mcp.Tool {
	return mcp.NewTool("ssh_download",
		mcp.WithDescription("Download a remote file to local (checksum + sensitive guard)."),
		mcp.WithString("host", mcp.Required(), mcp.Description("Host")),
		mcp.WithString("remote_path", mcp.Required(), mcp.Description("Remote file path")),
		mcp.WithString("local_path", mcp.Required(), mcp.Description("Local target path")),
		mcp.WithNumber("timeout", mcp.Description("Timeout seconds, default 60")),
		mcp.WithBoolean("allow_sensitive", mcp.Description("Allow sensitive paths, default false")),
	)
}

func sshFilesystemTool() mcp.Tool {
	return mcp.NewTool("ssh_filesystem",
		mcp.WithDescription("Remote filesystem ops: list / stat / mkdir / remove."),
		mcp.WithString("host", mcp.Required(), mcp.Description("Host")),
		mcp.WithString("action", mcp.Required(), mcp.Description("Action type"),
			mcp.Enum("list", "stat", "mkdir", "remove")),
		mcp.WithString("remote_path", mcp.Required(), mcp.Description("Remote path")),
		mcp.WithBoolean("parents", mcp.Description("mkdir -p, default true")),
		mcp.WithBoolean("recursive", mcp.Description("remove -r, default false")),
		mcp.WithBoolean("show_hidden", mcp.Description("list hidden files, default false")),
		mcp.WithNumber("timeout", mcp.Description("Timeout seconds, default 10")),
	)
}

func sshListHostsTool() mcp.Tool {
	return mcp.NewTool("ssh_list_hosts",
		mcp.WithDescription("List host aliases from ~/.ssh/config."),
	)
}

func sshGetReviewModeTool() mcp.Tool {
	return mcp.NewTool("ssh_get_review_mode",
		mcp.WithDescription("Get current review mode."),
	)
}

func sshSetReviewModeTool() mcp.Tool {
	return mcp.NewTool("ssh_set_review_mode",
		mcp.WithDescription("Switch review mode (off/whitelist/manual/smart)."),
		mcp.WithString("mode", mcp.Required(), mcp.Description("Review mode"),
			mcp.Enum("off", "whitelist", "manual", "smart")),
	)
}

func sshGetAuditLogsTool() mcp.Tool {
	return mcp.NewTool("ssh_get_audit_logs",
		mcp.WithDescription("Query recent behavior logs (read-only)."),
		mcp.WithNumber("limit", mcp.Description("Max records, default 50, max 500")),
		mcp.WithString("host", mcp.Description("Filter by host")),
		mcp.WithString("tool", mcp.Description("Filter by tool")),
		mcp.WithNumber("since_minutes", mcp.Description("Only last N minutes")),
	)
}

// Handlers ------------------------------------------------

func sshExecHandler(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := req.Params.Arguments
	host := strParam(args, "host", "")
	command := strParam(args, "command", "")
	timeout := intParam(args, "timeout", 30)
	shell := strParam(args, "shell", "")
	allowDangerous := boolParam(args, "allow_dangerous", false)

	if host == "" {
		return handleResult(results.MakeFailure(results.ErrorInvalidArgument, "host cannot be empty", "ssh_exec", "", "", nil, nil))
	}
	if timeout <= 0 {
		return handleResult(results.MakeFailure(results.ErrorInvalidArgument, "timeout must be > 0", "ssh_exec", host, "", nil, nil))
	}
	env := execWithReview(host, command, float64(timeout), allowDangerous, shell, nil)
	return handleResult(env)
}

func sshUploadHandler(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := req.Params.Arguments
	host := strParam(args, "host", "")
	localPath := strParam(args, "local_path", "")
	remotePath := strParam(args, "remote_path", "")
	timeout := intParam(args, "timeout", 60)
	overwrite := boolParam(args, "overwrite", false)

	if host == "" || localPath == "" || remotePath == "" {
		return handleResult(results.MakeFailure(results.ErrorInvalidArgument, "host/local_path/remote_path cannot be empty", "ssh_upload", host, "", nil, nil))
	}
	info, err := os.Stat(localPath)
	if err != nil || info.IsDir() {
		return handleResult(results.MakeFailure(results.ErrorInvalidArgument, "local file not found: "+localPath, "ssh_upload", host, "", nil, nil))
	}
	if info.Size() > maxSingleFileBytes {
		return handleResult(results.MakeFailure(results.ErrorResourceLimit,
			fmt.Sprintf("file exceeds size limit (%d bytes)", maxSingleFileBytes), "ssh_upload", host, "", nil, nil))
	}
	if review.SensitivePath(remotePath) {
		return handleResult(results.MakeFailure(results.ErrorInvalidArgument, "sensitive path blocked: "+remotePath, "ssh_upload", host, "", nil, nil))
	}
	if err := review.RejectTraversal(remotePath); err != nil {
		return handleResult(results.MakeFailure(results.ErrorInvalidArgument, err.Error(), "ssh_upload", host, "", nil, nil))
	}

	res := reviewEngine.Review(&review.Context{Tool: "ssh_upload", Command: "upload " + localPath + " -> " + remotePath, Host: host, Path: remotePath, Overwrite: overwrite})
	if !res.Approved {
		return handleResult(results.MakeRejected(res.Reason, "ssh_upload", host))
	}
	reviewInfo := &results.ReviewInfo{Mode: string(res.Mode), Decision: "approved", Risk: res.RiskLevel, Reason: res.Reason, PlanID: res.PlanID}

	connectTimeout := time.Duration(timeout) * time.Second
	if connectTimeout <= 0 {
		connectTimeout = 10 * time.Second
	}
	client, err := sshclient.Connect(host, connectTimeout)
	if err != nil {
		return handleResult(connectFailureEnvelope(err, "ssh_upload", host, reviewInfo))
	}
	defer client.Close()
	return handleResult(uploadFile(client, localPath, remotePath, overwrite, reviewInfo))
}

func sshDownloadHandler(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := req.Params.Arguments
	host := strParam(args, "host", "")
	remotePath := strParam(args, "remote_path", "")
	localPath := strParam(args, "local_path", "")
	timeout := intParam(args, "timeout", 60)
	allowSensitive := boolParam(args, "allow_sensitive", false)

	if host == "" || localPath == "" || remotePath == "" {
		return handleResult(results.MakeFailure(results.ErrorInvalidArgument, "host/remote_path/local_path cannot be empty", "ssh_download", host, "", nil, nil))
	}
	if !allowSensitive && review.SensitivePath(remotePath) {
		return handleResult(results.MakeFailure(results.ErrorInvalidArgument, "sensitive path blocked: "+remotePath, "ssh_download", host, "", nil, nil))
	}
	if err := review.RejectTraversal(remotePath); err != nil {
		return handleResult(results.MakeFailure(results.ErrorInvalidArgument, err.Error(), "ssh_download", host, "", nil, nil))
	}

	res := reviewEngine.Review(&review.Context{Tool: "ssh_download", Command: "download " + remotePath, Host: host, Path: remotePath})
	if !res.Approved {
		return handleResult(results.MakeRejected(res.Reason, "ssh_download", host))
	}
	reviewInfo := &results.ReviewInfo{Mode: string(res.Mode), Decision: "approved", Risk: res.RiskLevel, Reason: res.Reason, PlanID: res.PlanID}

	connectTimeout := time.Duration(timeout) * time.Second
	if connectTimeout <= 0 {
		connectTimeout = 10 * time.Second
	}
	client, err := sshclient.Connect(host, connectTimeout)
	if err != nil {
		return handleResult(connectFailureEnvelope(err, "ssh_download", host, reviewInfo))
	}
	defer client.Close()
	return handleResult(downloadFile(client, remotePath, localPath, reviewInfo))
}

func sshFilesystemHandler(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := req.Params.Arguments
	host := strParam(args, "host", "")
	action := strParam(args, "action", "")
	remotePath := strParam(args, "remote_path", "")
	parents := boolParam(args, "parents", true)
	recursive := boolParam(args, "recursive", false)
	showHidden := boolParam(args, "show_hidden", false)
	timeout := intParam(args, "timeout", 10)

	if host == "" {
		return handleResult(results.MakeFailure(results.ErrorInvalidArgument, "host cannot be empty", "ssh_filesystem", "", "", nil, nil))
	}
	if strings.TrimSpace(remotePath) == "" {
		return handleResult(results.MakeFailure(results.ErrorInvalidArgument, "remote_path cannot be empty", "ssh_filesystem", host, "", nil, nil))
	}
	switch action {
	case "list", "stat", "mkdir", "remove":
	default:
		return handleResult(results.MakeFailure(results.ErrorInvalidArgument, "unsupported action: "+action, "ssh_filesystem", host, "", nil, nil))
	}

	if review.SensitivePath(remotePath) {
		return handleResult(results.MakeFailure(results.ErrorInvalidArgument, "sensitive path blocked: "+remotePath, "ssh_filesystem", host, "", nil, nil))
	}
	if err := review.RejectTraversal(remotePath); err != nil {
		return handleResult(results.MakeFailure(results.ErrorInvalidArgument, err.Error(), "ssh_filesystem", host, "", nil, nil))
	}

	var res *review.Result
	if action == "mkdir" || action == "remove" {
		res = reviewEngine.Review(&review.Context{
			Tool: "ssh_filesystem", Command: fmt.Sprintf("%s %s", action, remotePath),
			Host: host, Path: remotePath, AllowDangerous: action == "remove" && recursive,
		})
		if !res.Approved {
			return handleResult(results.MakeRejected(res.Reason, "ssh_filesystem", host))
		}
	} else {
		res = &review.Result{Approved: true, Mode: reviewEngine.Mode(), Reason: "read-only op", RiskLevel: "low", PlanID: ""}
	}
	reviewInfo := &results.ReviewInfo{Mode: string(res.Mode), Decision: "approved", Risk: res.RiskLevel, Reason: res.Reason, PlanID: res.PlanID}

	switch action {
	case "list":
		return handleResult(fsList(host, remotePath, showHidden, timeout, reviewInfo))
	case "stat":
		return handleResult(fsStat(host, remotePath, timeout, reviewInfo))
	case "mkdir":
		return handleResult(fsMkdir(host, remotePath, parents, timeout, reviewInfo))
	case "remove":
		return handleResult(fsRemove(host, remotePath, recursive, timeout, reviewInfo))
	}
	return handleResult(results.MakeFailure(results.ErrorInvalidArgument, "unsupported action: "+action, "ssh_filesystem", host, "", nil, nil))
}

func sshListHostsHandler(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	entries, text := listHosts()
	env := results.MakeSuccess("ssh_list_hosts", "", map[string]interface{}{"hosts": entries}, text, nil)
	return handleResult(env)
}

func sshGetReviewModeHandler(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	status := reviewEngine.GetStatus()
	env := results.MakeSuccess("ssh_get_review_mode", "", status,
		fmt.Sprintf("current review mode: %s", status["mode"]), nil)
	return handleResult(env)
}

func sshSetReviewModeHandler(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := req.Params.Arguments
	mode := strParam(args, "mode", "")
	err := reviewEngine.SetMode(review.Mode(mode))
	if err != nil {
		return handleResult(results.MakeFailure(results.ErrorInvalidArgument, err.Error(), "ssh_set_review_mode", "", "", nil, nil))
	}
	env := results.MakeSuccess("ssh_set_review_mode", "",
		map[string]interface{}{"mode": mode},
		"review mode switched to: "+mode, nil)
	return handleResult(env)
}

func sshGetAuditLogsHandler(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := req.Params.Arguments
	limit := intParam(args, "limit", 50)
	host := strParam(args, "host", "")
	tool := strParam(args, "tool", "")
	since := intParam(args, "since_minutes", 0)

	records, total, err := audit.Query(audit.QueryOptions{
		Host: host, Tool: tool, SinceMinute: since, Limit: limit,
	})
	if err != nil {
		return handleResult(results.MakeFailure(results.ErrorLocalIOError, err.Error(), "ssh_get_audit_logs", "", "", nil, nil))
	}
	text := audit.RenderText(records, total)
	recList := make([]interface{}, len(records))
	for i, r := range records {
		recList[i] = r
	}
	env := results.MakeSuccess("ssh_get_audit_logs", "",
		map[string]interface{}{"records": recList, "total": total, "truncated": len(records) < total},
		text, nil)
	return handleResult(env)
}
