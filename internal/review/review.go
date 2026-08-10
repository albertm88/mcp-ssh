// Package review 实现四模式审核引擎（与 Python 版完全兼容）：
// off / whitelist / manual / smart。
package review

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Mode 是审核模式。
type Mode string

const (
	ModeOff       Mode = "off"
	ModeWhitelist Mode = "whitelist"
	ModeManual    Mode = "manual"
	ModeSmart     Mode = "smart"
)

// Context 是一次待审核操作的计划。
type Context struct {
	Tool            string
	Command         string
	Host            string
	Path            string
	AllowDangerous  bool
	Shell           string
	Environment     []string
	EnvironmentName []string
	EnvironmentDgt  string
	Recursive       bool
	Overwrite       bool
}

// PlanID 计算操作计划的稳定摘要（与 Python 版 plan_id 语义一致）。
func (c *Context) PlanID() string {
	h := sha256Hex(c.Tool + "\x00" + c.Command + "\x00" + c.Host + "\x00" + c.Path)
	return h
}

// Result 是一次审核决策。
type Result struct {
	Approved  bool
	Mode      Mode
	Reason    string
	RiskLevel string
	ElapsedMs int64
	PlanID    string
}

// RejectedError 表示审核拒绝。
type RejectedError struct{ Reason string }

func (e *RejectedError) Error() string { return e.Reason }

// Engine 是审核引擎门面。
type Engine struct {
	mode      Mode
	whitelist []*regexp.Regexp
}

// NewEngine 从环境变量构建引擎（SSH_REVIEW_MODE，默认 whitelist，与 Python 版一致）。
func NewEngine() *Engine {
	mode := ModeWhitelist
	if v := strings.ToLower(strings.TrimSpace(os.Getenv("SSH_REVIEW_MODE"))); v != "" {
		switch Mode(v) {
		case ModeOff, ModeWhitelist, ModeManual, ModeSmart:
			mode = Mode(v)
		}
	}
	return &Engine{
		mode:      mode,
		whitelist: loadWhitelist(),
	}
}

func (e *Engine) Mode() Mode { return e.mode }

// SetMode 切换审核模式；无效值返回错误且不改变状态。
func (e *Engine) SetMode(m Mode) error {
	switch m {
	case ModeOff, ModeWhitelist, ModeManual, ModeSmart:
		e.mode = m
		return nil
	default:
		return fmt.Errorf("无效审核模式：%s", m)
	}
}

// GetStatus 返回审核状态。
func (e *Engine) GetStatus() map[string]interface{} {
	return map[string]interface{}{
		"mode":           string(e.mode),
		"whitelist_file": os.Getenv("SSH_REVIEW_WHITELIST_FILE"),
		"manual_timeout": 60,
	}
}

// 默认白名单规则（与 Python 版 WhitelistReviewer 一致）。
var defaultWhitelistRules = []string{
	`^ls\b`, `^ll\b`, `^pwd$`, `^whoami$`, `^hostname$`,
	`^uname\b`, `^df\b`, `^free\b`, `^uptime$`, `^date$`,
	`^cat\s+[^|;&]+$`, `^head\s+[^|;&]+$`, `^tail\s+[^|;&]+$`,
	`^grep\s+[^|;&]+$`, `^find\s+[^|;&]+$`, `^wc\s+[^|;&]+$`,
	`^echo\s+[^|;&]*$`, `^ping\s+[^|;&]+$`, `^ps\b`,
	`^top\s+-b`, `^htop\s+-b`, `^docker\s+ps\b`, `^docker\s+logs\b`,
	`^systemctl\s+status\b`, `^journalctl\s+[^|;&]+$`,
	`^mkdir\s+[^|;&]+$`, `^touch\s+[^|;&]+$`, `^cp\s+[^|;&]+$`,
	`^mv\s+[^|;&]+$`, `^scp\s+[^|;&]+$`, `^rsync\s+[^|;&]+$`,
	`^chmod\s+[0-7]{3,4}\s+[^|;&]+$`, `^chown\s+[^|;&]+$`,
	`^tar\s+[^|;&]+$`, `^zip\s+[^|;&]+$`, `^unzip\s+[^|;&]+$`,
	`^git\s+(status|log|diff|show|branch|checkout|pull|fetch|clone)\b`,
}

func loadWhitelist() []*regexp.Regexp {
	patterns := []*regexp.Regexp{}
	for _, rule := range defaultWhitelistRules {
		if re, err := regexp.Compile(rule); err == nil {
			patterns = append(patterns, re)
		}
	}
	if file := os.Getenv("SSH_REVIEW_WHITELIST_FILE"); file != "" {
		if f, err := os.Open(file); err == nil {
			defer f.Close()
			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				if re, err := regexp.Compile(line); err == nil {
					patterns = append(patterns, re)
				}
			}
		}
	}
	return patterns
}

// 危险命令拦截（防御纵深，所有模式生效，与 Python 版一致）。
// Go regexp 不支持负向前瞻，改用「rm 根路径检查」+「独立危险模式」组合。
var dangerousRM = regexp.MustCompile(`(?i)^\s*rm\s+(-rf?|--recursive)\s+/`)

var dangerousOthers = regexp.MustCompile(`(?i)mkfs|dd\s+if=|format\s+[a-z]:|shutdown|reboot|halt|poweroff|:\(\)\s*\{.*\};:|fork\s*bomb`)

// 注入特征检测（防御纵深，所有模式生效，无豁免）。
var injectionPatterns = regexp.MustCompile(`(?i);\s*(rm|wget|curl|nc|ncat|bash|sh|chmod|chown|passwd|useradd)|/dev/(tcp|udp)/|wget\s+https?://.*\|\s*(sh|bash)|curl\s+https?://.*\|\s*(sh|bash)|nc\s+.*-e|ncat\s+.*-e|\|\s*(sh|bash|zsh|python|perl)\s*$`)

// 敏感路径保护。
var sensitivePaths = regexp.MustCompile(`(?i)/etc/(passwd|shadow|ssh/sshd_config|sudoers)|/root/\.ssh/|~/.ssh/id_`)

// SensitivePath 检查路径是否命中敏感路径保护。
func SensitivePath(p string) bool { return sensitivePaths.MatchString(p) }

// RejectTraversal 拒绝包含 . / .. 组件的路径。
func RejectTraversal(p string) error {
	for _, c := range strings.Split(p, "/") {
		if c == "." || c == ".." {
			return fmt.Errorf("远端路径包含不受支持的 . / .. 组件：%s", p)
		}
	}
	return nil
}

// InsecureHost 检查审核模式是否跳过主机校验。
func InsecureHost(tool string) bool {
	switch tool {
	case "ssh_get_review_mode", "ssh_set_review_mode", "ssh_list_hosts":
		return true
	default:
		return false
	}
}

// ValidateCommand 执行防御纵深校验（在审核之前，所有模式生效）。
// 返回错误表示命令被拦截。
func ValidateCommand(command string, allowDangerous bool) error {
	if strings.TrimSpace(command) == "" {
		return fmt.Errorf("命令不能为空")
	}
	if len(command) > 10000 {
		return fmt.Errorf("命令长度超过限制（最大10000字符）")
	}
	if !allowDangerous {
		if dangerousOthers.MatchString(command) {
			return fmt.Errorf("命令命中危险命令拦截列表，如需执行请设置 allow_dangerous=True")
		}
		// rm 根路径：匹配 rm -rf / 后跟非 tmp/var/tmp 的路径
		if m := dangerousRM.FindStringSubmatch(command); m != nil {
			after := strings.TrimSpace(command[len(m[0]):])
			if after != "" && !strings.HasPrefix(after, "tmp") && !strings.HasPrefix(after, "var/tmp") {
				return fmt.Errorf("命令命中危险命令拦截列表，如需执行请设置 allow_dangerous=True")
			}
			if after == "" {
				return fmt.Errorf("命令命中危险命令拦截列表，如需执行请设置 allow_dangerous=True")
			}
		}
	}
	if injectionPatterns.MatchString(command) {
		return fmt.Errorf("命令命中注入特征检测，已拒绝执行")
	}
	return nil
}

// Review 执行四模式审核。
func (e *Engine) Review(ctx *Context) *Result {
	// 无效上下文（所有模式都不放行）
	if strings.TrimSpace(ctx.Tool) == "" {
		return deny(ctx, "工具名称不能为空", "high")
	}
	if strings.HasPrefix(ctx.Tool, "ssh_") && !InsecureHost(ctx.Tool) && strings.TrimSpace(ctx.Host) == "" {
		return deny(ctx, "SSH 操作缺少目标主机", "high")
	}

	switch e.mode {
	case ModeOff:
		return &Result{Approved: true, Mode: ModeOff, Reason: "审核已关闭，直接放行", RiskLevel: "unknown", PlanID: ctx.PlanID()}
	case ModeWhitelist:
		return e.reviewWhitelist(ctx)
	case ModeManual:
		return e.reviewManual(ctx)
	case ModeSmart:
		return e.reviewSmart(ctx)
	}
	return deny(ctx, "未知审核模式", "high")
}

func deny(ctx *Context, reason, risk string) *Result {
	return &Result{Approved: false, Mode: ModeWhitelist, Reason: reason, RiskLevel: risk, PlanID: ctx.PlanID()}
}

// reviewWhitelist 仅允许白名单规则，拒绝控制运算符。
func (e *Engine) reviewWhitelist(ctx *Context) *Result {
	cmd := strings.TrimSpace(ctx.Command)
	for _, token := range []string{"\n", "\r", ";", "&&", "||", "`", "$("} {
		if strings.Contains(cmd, token) {
			return deny(ctx, "白名单模式不允许 shell 控制运算符或多行命令", "medium")
		}
	}
	for _, re := range e.whitelist {
		if re.MatchString(cmd) {
			return &Result{Approved: true, Mode: ModeWhitelist, Reason: "匹配白名单规则: " + re.String(), RiskLevel: "low", PlanID: ctx.PlanID()}
		}
	}
	return deny(ctx, "命令不在白名单中，拒绝执行。可通过 ssh_set_review_mode 切换模式或添加白名单规则。", "medium")
}

// 危险命令黑名单（smart 模式高置信度拒绝）。
var smartBlacklist = []*regexp.Regexp{
	regexp.MustCompile(`(?i)rm\s+-rf\s+/[^\s]`),
	regexp.MustCompile(`(?i)mkfs|dd\s+if=|format\s+[a-z]:`),
	regexp.MustCompile(`(?i)shutdown|reboot|halt|poweroff`),
	regexp.MustCompile(`(?i):\(\)\s*\{.*\};:`),
	regexp.MustCompile(`(?i)curl\s+.*\|\s*(sh|bash)|wget\s+.*\|\s*(sh|bash)`),
	regexp.MustCompile(`(?i)nc\s+.*-e|ncat\s+.*-e`),
	regexp.MustCompile(`(?i)/dev/(tcp|udp)/`),
}

// 安全命令白名单（smart 模式高置信度放行）。
var smartSafe = []*regexp.Regexp{
	regexp.MustCompile(`(?i)^(ls|ll|pwd|whoami|hostname|uname|df|free|uptime|date)$`),
	regexp.MustCompile(`(?i)^(cat|head|tail|grep|find|wc|echo|ping|ps)\s+[^\r\n|;&]*$`),
	regexp.MustCompile(`(?i)^git\s+(status|log|diff|show|branch)$`),
}

// reviewManual 人工确认（MCP elicitation 或本地终端；无通道则 fail-closed）。
func (e *Engine) reviewManual(ctx *Context) *Result {
	reason, ok := manualConfirm(ctx)
	if ok {
		return &Result{Approved: true, Mode: ModeManual, Reason: "人工确认通过", RiskLevel: "medium", PlanID: ctx.PlanID()}
	}
	return deny(ctx, reason, "high")
}

// reviewSmart 黑名单拒绝 → 安全白名单放行 → 降级人工。
func (e *Engine) reviewSmart(ctx *Context) *Result {
	cmd := strings.TrimSpace(ctx.Command)
	for _, re := range smartBlacklist {
		if re.MatchString(cmd) {
			return &Result{Approved: false, Mode: ModeSmart, Reason: "命中危险命令黑名单: " + re.String() + "。如需执行请设置 allow_dangerous=True。", RiskLevel: "critical", PlanID: ctx.PlanID()}
		}
	}
	for _, re := range smartSafe {
		if re.MatchString(cmd) {
			return &Result{Approved: true, Mode: ModeSmart, Reason: "匹配安全命令白名单: " + re.String(), RiskLevel: "low", PlanID: ctx.PlanID()}
		}
	}
	reason, ok := manualConfirm(ctx)
	if ok {
		return &Result{Approved: true, Mode: ModeSmart, Reason: "智能审核转人工确认通过", RiskLevel: "medium", PlanID: ctx.PlanID()}
	}
	return deny(ctx, "智能审核无法判定且无人工通道： "+reason, "high")
}

// manualConfirm 尝试人工确认（stdin 终端交互）。MCP elicitation 由 server 层处理。
func manualConfirm(ctx *Context) (string, bool) {
	if !isatty() {
		return "当前客户端不支持人工确认（无 elicitation capability 且非本地终端）。请切换 smart/whitelist 模式。", false
	}
	fmt.Fprintf(os.Stderr, "\n[审核] 工具=%s 主机=%s 命令=%s\n允许执行？(y/N): ", ctx.Tool, ctx.Host, ctx.Command)
	reader := bufio.NewReader(os.Stdin)
	line, _ := reader.ReadString('\n')
	if strings.TrimSpace(strings.ToLower(line)) == "y" {
		return "", true
	}
	return "人工确认拒绝执行", false
}

func isatty() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

// WhitelistFilePath 返回默认白名单文件路径（兼容 SSH_REVIEW_WHITELIST_FILE）。
func WhitelistFilePath() string {
	if v := os.Getenv("SSH_REVIEW_WHITELIST_FILE"); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".ssh", "mcp-ssh-whitelist.conf")
}
