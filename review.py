"""SSH 操作审核引擎。

四种审核模式：
  - off:        关闭审核，所有操作直接放行（仅记日志）
  - whitelist:  白名单审核，仅允许匹配白名单规则的命令
  - manual:     人工审核，每条命令挂起等待人工确认（stdio 交互）
  - smart:      智能审核，本地规则初筛 → 不确定时降级为人工确认

设计原则：安全、可控、灵活
  - 安全：默认 whitelist 模式，最小权限原则
  - 可控：运行时可通过 MCP 工具动态切换模式
  - 灵活：支持环境变量配置 + 白名单文件自定义
"""
from __future__ import annotations

import os
import hashlib
import json
import re
import sys
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Mapping, Optional

from logger import get_logger

_log = get_logger()


def build_environment_plan(
    environment: Mapping[str, str] | None,
) -> tuple[dict[str, str], tuple[str, ...], str]:
    """Normalize environment names and return a value-safe plan digest."""
    if not environment:
        return {}, (), ""

    normalized: dict[str, str] = {}
    for raw_name, value in environment.items():
        if not isinstance(raw_name, str) or not isinstance(value, str):
            raise TypeError("environment 必须是字符串键值对")
        name = raw_name.strip()
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            raise ValueError(f"非法环境变量名: {raw_name}")
        normalized[name] = value

    canonical = json.dumps(
        sorted(normalized.items()),
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    digest = hashlib.sha256(canonical).hexdigest()
    return normalized, tuple(sorted(normalized)), digest


# ---------------------------------------------------------------------------
# manual 多通道自动适配
# ---------------------------------------------------------------------------

def _client_supports_elicitation(mcp_ctx: Any) -> bool:
    """检测 MCP 客户端是否声明 elicit capability。"""
    if mcp_ctx is None:
        return False
    try:
        capabilities = getattr(mcp_ctx.session, "client_params", None)
        if capabilities is None:
            return False
        elicitation = getattr(capabilities.capabilities, "elicitation", None)
        return elicitation is not None
    except Exception:
        return False


def _select_manual_channel(mcp_ctx: Any) -> tuple[str, str]:
    """选择 manual 确认通道：elicit / local / reject。

    返回 (channel, error_message)。
    channel: "elicit" | "local" | "reject"
    SSH_REVIEW_MANUAL_CHANNEL=elicit|local|auto 可显式覆盖（默认 auto）。
    """
    forced = os.getenv("SSH_REVIEW_MANUAL_CHANNEL", "auto").strip().lower()

    if forced == "elicit":
        if not _client_supports_elicitation(mcp_ctx):
            return "reject", "客户端不支持 elicit 弹框（未声明 elicitation capability），无法人工确认。请切 smart/whitelist 或检查客户端。"
        return "elicit", ""

    if forced == "local":
        if not sys.stdin.isatty():
            return "reject", "SSH_REVIEW_MANUAL_CHANNEL=local 但当前无本地终端（stdin 非 tty）。"
        return "local", ""

    # auto：按客户端能力自动适配
    if _client_supports_elicitation(mcp_ctx):
        return "elicit", ""
    if sys.stdin.isatty():
        return "local", ""
    return "reject", "当前客户端不支持人工确认（无 elicitation capability 且非本地终端）。请切换 smart/whitelist 模式。"


# ---------------------------------------------------------------------------
# 审核模式枚举
# ---------------------------------------------------------------------------

class ReviewMode(Enum):
    """审核模式枚举。"""
    OFF = "off"
    WHITELIST = "whitelist"
    MANUAL = "manual"
    SMART = "smart"

    @classmethod
    def from_env(cls, key: str = "SSH_REVIEW_MODE", default: "ReviewMode" = None) -> "ReviewMode":
        if default is None:
            default = cls.WHITELIST
        name = os.getenv(key, "").lower().strip()
        try:
            return cls(name)
        except ValueError:
            _log.warning("invalid_review_mode", value=name, default=default.value)
            return default


# ---------------------------------------------------------------------------
# 审核结果
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ReviewResult:
    """审核结果。"""
    approved: bool
    mode: str
    reason: str = ""
    risk_level: str = "unknown"  # low / medium / high / critical
    elapsed: float = 0.0
    plan_id: str = ""

    def __bool__(self) -> bool:
        return self.approved


# ---------------------------------------------------------------------------
# 审核上下文
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ReviewContext:
    """审核绑定的不可变操作计划。"""
    tool: str  # 调用的工具名，如 ssh_exec / ssh_upload
    command: str = ""  # 要执行的命令
    host: str = ""  # 目标主机
    path: str = ""  # 涉及的路径（文件操作时）
    allow_dangerous: bool = False  # 是否显式允许危险操作
    shell: Optional[str] = None
    environment: tuple[str, ...] = ()  # 只记录变量名，不记录敏感值
    local_path: str = ""
    remote_path: str = ""
    recursive: bool = False
    overwrite: bool = False
    environment_digest: str = ""
    mcp_ctx: Any = field(default=None, repr=False, compare=False)  # MCP Context（manual 弹框用）

    def __post_init__(self) -> None:
        string_fields = {
            "tool": self.tool,
            "command": self.command,
            "host": self.host,
            "path": self.path,
            "local_path": self.local_path,
            "remote_path": self.remote_path,
        }
        if self.shell is not None:
            string_fields["shell"] = self.shell
        for name, value in string_fields.items():
            if not isinstance(value, str):
                raise TypeError(f"{name} 必须是字符串")
        if not isinstance(self.environment, tuple) or not all(
            isinstance(name, str) for name in self.environment
        ):
            raise TypeError("environment 必须是环境变量名称元组")
        if not isinstance(self.environment_digest, str):
            raise TypeError("environment_digest 必须是字符串")
        if not isinstance(self.allow_dangerous, bool):
            raise TypeError("allow_dangerous 必须是布尔值")
        if not isinstance(self.recursive, bool):
            raise TypeError("recursive 必须是布尔值")
        if not isinstance(self.overwrite, bool):
            raise TypeError("overwrite 必须是布尔值")

    @property
    def plan_id(self) -> str:
        """返回绑定所有执行字段的稳定摘要。"""
        payload = {
            "tool": self.tool,
            "command": self.command,
            "host": self.host,
            "path": self.path,
            "allow_dangerous": self.allow_dangerous,
            "shell": self.shell,
            "environment": self.environment,
            "local_path": self.local_path,
            "remote_path": self.remote_path,
            "recursive": self.recursive,
            "overwrite": self.overwrite,
            "environment_digest": self.environment_digest,
        }
        encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


# ---------------------------------------------------------------------------
# 基础审核器
# ---------------------------------------------------------------------------

class BaseReviewer:
    """审核器基类。"""

    def __init__(self, config: "ReviewConfig") -> None:
        self.config = config

    def review(self, ctx: ReviewContext) -> ReviewResult:
        raise NotImplementedError

    def _invalid_context(self, ctx: ReviewContext, mode: str) -> ReviewResult | None:
        """审核模式可关闭，但无效操作计划不能被放行。"""
        reason = ""
        if not ctx.tool.strip():
            reason = "工具名称不能为空"
        elif ctx.tool.startswith("ssh_") and ctx.tool not in {
            "ssh_get_review_mode",
            "ssh_set_review_mode",
            "ssh_list_hosts",
            "ssh_scan",
        } and not ctx.host.strip():
            reason = "SSH 操作缺少目标主机"
        if not reason:
            return None
        return ReviewResult(
            approved=False,
            mode=mode,
            reason=reason,
            risk_level="high",
            plan_id=ctx.plan_id,
        )

    def _log_audit(self, ctx: ReviewContext, result: ReviewResult) -> None:
        """记录审计日志。"""
        _log.info(
            "review_audit",
            tool=ctx.tool,
            mode=result.mode,
            approved=result.approved,
            risk_level=result.risk_level,
            reason=result.reason,
            plan_id=ctx.plan_id,
            command_length=len(ctx.command),
            host=ctx.host,
            environment_count=len(ctx.environment),
            elapsed=round(result.elapsed, 3),
        )


# ---------------------------------------------------------------------------
# 关闭审核
# ---------------------------------------------------------------------------

class OffReviewer(BaseReviewer):
    """关闭审核：所有操作直接放行。"""

    def review(self, ctx: ReviewContext) -> ReviewResult:
        t0 = time.monotonic()
        if (invalid := self._invalid_context(ctx, "off")) is not None:
            self._log_audit(ctx, invalid)
            return invalid
        result = ReviewResult(
            approved=True,
            mode="off",
            reason="审核已关闭，直接放行",
            risk_level="unknown",
            elapsed=time.monotonic() - t0,
            plan_id=ctx.plan_id,
        )
        self._log_audit(ctx, result)
        return result


# ---------------------------------------------------------------------------
# 白名单审核
# ---------------------------------------------------------------------------

class WhitelistReviewer(BaseReviewer):
    """白名单审核：仅允许匹配白名单规则的命令。"""

    def __init__(self, config: "ReviewConfig") -> None:
        super().__init__(config)
        self._whitelist = self._load_whitelist()

    def _load_whitelist(self) -> list[re.Pattern]:
        """加载白名单规则文件。"""
        patterns: list[re.Pattern] = []
        wl_file = self.config.whitelist_file

        # 默认白名单（基础安全命令）
        default_rules = [
            r"^ls\b", r"^ll\b", r"^pwd$", r"^whoami$", r"^hostname$",
            r"^uname\b", r"^df\b", r"^free\b", r"^uptime$", r"^date$",
            r"^cat\s+[^|;&]+$", r"^head\s+[^|;&]+$", r"^tail\s+[^|;&]+$",
            r"^grep\s+[^|;&]+$", r"^find\s+[^|;&]+$", r"^wc\s+[^|;&]+$",
            r"^echo\s+[^|;&]*$", r"^ping\s+[^|;&]+$", r"^ps\b",
            r"^top\s+-b", r"^htop\s+-b", r"^docker\s+ps\b", r"^docker\s+logs\b",
            r"^systemctl\s+status\b", r"^journalctl\s+[^|;&]+$",
            r"^mkdir\s+[^|;&]+$", r"^touch\s+[^|;&]+$", r"^cp\s+[^|;&]+$",
            r"^mv\s+[^|;&]+$", r"^scp\s+[^|;&]+$", r"^rsync\s+[^|;&]+$",
            r"^chmod\s+[0-7]{3,4}\s+[^|;&]+$", r"^chown\s+[^|;&]+$",
            r"^tar\s+[^|;&]+$", r"^zip\s+[^|;&]+$", r"^unzip\s+[^|;&]+$",
            r"^git\s+(status|log|diff|show|branch|checkout|pull|fetch|clone)\b",
        ]

        # 从文件加载自定义规则
        if wl_file and wl_file.exists():
            try:
                with wl_file.open("r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        try:
                            patterns.append(re.compile(line, re.IGNORECASE))
                        except re.error as e:
                            _log.warning("invalid_whitelist_rule", rule=line, error=str(e))
                _log.info("whitelist_loaded", file=str(wl_file), rules=len(patterns))
            except OSError as e:
                _log.error("whitelist_load_failed", file=str(wl_file), error=str(e))

        # 加载默认规则
        for rule in default_rules:
            try:
                patterns.append(re.compile(rule, re.IGNORECASE))
            except re.error:
                pass

        return patterns

    def review(self, ctx: ReviewContext) -> ReviewResult:
        t0 = time.monotonic()
        if (invalid := self._invalid_context(ctx, "whitelist")) is not None:
            self._log_audit(ctx, invalid)
            return invalid
        cmd = ctx.command.strip()

        # 内置白名单只允许单条命令，控制运算符必须由人工/智能模式审核。
        if any(token in cmd for token in ("\n", "\r", ";", "&&", "||", "`", "$(")):
            result = ReviewResult(
                approved=False,
                mode="whitelist",
                reason="白名单模式不允许 shell 控制运算符或多行命令",
                risk_level="medium",
                elapsed=time.monotonic() - t0,
                plan_id=ctx.plan_id,
            )
            self._log_audit(ctx, result)
            return result

        # 检查是否匹配白名单
        for pattern in self._whitelist:
            if pattern.search(cmd):
                result = ReviewResult(
                    approved=True,
                    mode="whitelist",
                    reason=f"匹配白名单规则: {pattern.pattern}",
                    risk_level="low",
                    elapsed=time.monotonic() - t0,
                    plan_id=ctx.plan_id,
                )
                self._log_audit(ctx, result)
                return result

        # 未匹配白名单
        result = ReviewResult(
            approved=False,
            mode="whitelist",
            reason="命令不在白名单中，拒绝执行。可通过 ssh_set_review_mode 切换模式或添加白名单规则。",
            risk_level="medium",
            elapsed=time.monotonic() - t0,
            plan_id=ctx.plan_id,
        )
        self._log_audit(ctx, result)
        return result


# ---------------------------------------------------------------------------
# 人工审核
# ---------------------------------------------------------------------------

class ManualReviewer(BaseReviewer):
    """人工审核：每条命令挂起等待人工确认（stdio 交互）。"""

    def review(self, ctx: ReviewContext) -> ReviewResult:
        t0 = time.monotonic()
        if (invalid := self._invalid_context(ctx, "manual")) is not None:
            self._log_audit(ctx, invalid)
            return invalid

        # 选择确认通道（elicit / local / fail-closed）
        channel, channel_error = _select_manual_channel(ctx.mcp_ctx)
        client_name = ""
        if ctx.mcp_ctx is not None:
            sess = getattr(ctx.mcp_ctx, "session", None)
            if sess is not None:
                cp = getattr(sess, "client_params", None)
                ci = getattr(cp, "clientInfo", None) if cp is not None else None
                client_name = getattr(ci, "name", "") or ""
        _log.info(
            "manual_channel_fallback",
            channel=channel,
            error=channel_error or "",
            client=client_name,
        )

        if channel == "reject":
            result = ReviewResult(
                approved=False,
                mode="manual",
                reason=channel_error or "当前客户端不支持人工确认",
                risk_level="high",
                elapsed=time.monotonic() - t0,
                plan_id=ctx.plan_id,
            )
            self._log_audit(ctx, result)
            return result

        if channel == "elicit":
            approved = self._wait_elicitation(ctx)
        else:
            approved = self._wait_confirmation_local(ctx)

        result = ReviewResult(
            approved=approved,
            mode="manual",
            reason="人工批准" if approved else "人工拒绝或超时",
            risk_level="medium" if approved else "high",
            elapsed=time.monotonic() - t0,
            plan_id=ctx.plan_id,
        )
        self._log_audit(ctx, result)
        return result

    def _wait_elicitation(self, ctx: ReviewContext) -> bool:
        """经 MCP Elicitation 弹框等待人工确认。"""
        mcp_ctx = ctx.mcp_ctx
        if mcp_ctx is None:
            _log.warning("manual_channel_fallback", channel="reject", error="elicit 通道但无 MCP Context")
            return False
        _log.info("manual_confirm_requested", tool=ctx.tool, host=ctx.host, plan_id=ctx.plan_id)
        try:
            from pydantic import BaseModel, Field
            from typing import Literal

            class ManualDecision(BaseModel):
                decision: Literal["allow", "reject"] = Field(..., description="允许执行或拒绝")

            result = mcp_ctx.elicit(
                message=(
                    "[manual 审核] 工具=%s host=%s 命令=%s 路径=%s 危险等级=%s plan_id=%s"
                    % (ctx.tool, ctx.host or "-", ctx.command[:200], ctx.path or "-",
                       "high" if ctx.allow_dangerous else "normal", ctx.plan_id)
                ),
                schema=ManualDecision,
            )
            approved = bool(
                getattr(result, "action", None) == "accept"
                and getattr(getattr(result, "data", None), "decision", None) == "allow"
            )
            _log.info("manual_confirm_result", tool=ctx.tool, host=ctx.host,
                      approved=approved, action=getattr(result, "action", None))
            return approved
        except Exception as e:
            _log.error("manual_confirm_elicitation_error", error=str(e))
            return False

    def _safe_print(self, text: str, **kwargs) -> None:
        """跨平台安全打印，避免 Windows GBK 编码 emoji 失败。"""
        try:
            print(text, **kwargs)
        except UnicodeEncodeError:
            # 移除 emoji 后重试
            import re as _re
            text_no_emoji = _re.sub(r'[^\x00-\x7F]+', '', text)
            print(text_no_emoji, **kwargs)

    def _print_review_banner(self, ctx: ReviewContext) -> None:
        """打印审核横幅到 stderr（避免干扰 stdout 的 MCP 协议）。"""
        banner = f"""
{'='*70}
[人工审核] 待执行命令
{'='*70}
  工具:     {ctx.tool}
  主机:     {ctx.host or 'N/A'}
  命令:     {ctx.command[:200]}
  Shell:    {ctx.shell or 'default'}
  路径:     {ctx.path or 'N/A'}
  本地路径: {ctx.local_path or 'N/A'}
  远端路径: {ctx.remote_path or 'N/A'}
  环境变量: {', '.join(ctx.environment) or 'N/A'}
  递归/覆盖: {ctx.recursive}/{ctx.overwrite}
  计划摘要: {ctx.plan_id}
  危险标记: {ctx.allow_dangerous}
{'='*70}
请在 {self.config.manual_timeout}s 内确认：
  [y/yes] 批准执行
  [n/no]  拒绝执行（默认）
{'='*70}
""".strip()
        self._safe_print(banner, file=sys.stderr, flush=True)

    def _wait_confirmation_local(self, ctx: ReviewContext) -> bool:
        """本地终端等待人工确认，支持超时。"""
        self._print_review_banner(ctx)
        # MCP stdio 独占 stdin；非交互环境必须失败关闭，不能消费协议帧。
        if not sys.stdin.isatty():
            self._safe_print(
                "[拒绝] 当前客户端未提供独立人工审核通道",
                file=sys.stderr,
                flush=True,
            )
            return False

        timeout = self.config.manual_timeout
        deadline = time.monotonic() + timeout

        self._safe_print(f"[等待确认] (剩余 {timeout}s): ", end="", file=sys.stderr, flush=True)

        while time.monotonic() < deadline:
            # 非阻塞读取 stdin
            if sys.stdin in self._get_ready_fds():
                try:
                    line = sys.stdin.readline().strip().lower()
                    if line in ("y", "yes"):
                        self._safe_print("[已批准]", file=sys.stderr, flush=True)
                        return True
                    elif line in ("n", "no", ""):
                        self._safe_print("[已拒绝]", file=sys.stderr, flush=True)
                        return False
                except (EOFError, KeyboardInterrupt):
                    return False

            remaining = int(deadline - time.monotonic())
            if remaining % 10 == 0 and remaining > 0:
                self._safe_print(f"{remaining}s ", end="", file=sys.stderr, flush=True)
            time.sleep(0.1)

        self._safe_print(f"\n[超时] ({timeout}s)，自动拒绝", file=sys.stderr, flush=True)
        return False

    @staticmethod
    def _get_ready_fds() -> list:
        """跨平台获取可读的 stdin 文件描述符。"""
        import select
        try:
            # Windows 下 select 不支持 stdin，用 msvcrt
            if sys.platform == "win32":
                import msvcrt
                return [sys.stdin] if msvcrt.kbhit() else []
            else:
                return select.select([sys.stdin], [], [], 0)[0]
        except Exception:
            return []


# ---------------------------------------------------------------------------
# 智能审核
# ---------------------------------------------------------------------------

class SmartReviewer(BaseReviewer):
    """智能审核：本地规则初筛 → 不确定时降级为人工确认。"""

    def __init__(self, config: "ReviewConfig") -> None:
        super().__init__(config)
        self._whitelist_reviewer = WhitelistReviewer(config)
        self._manual_reviewer = ManualReviewer(config)

        # 危险命令黑名单（高置信度拒绝）
        self._blacklist = [
            re.compile(r"rm\s+-rf\s+/(?!\w)", re.IGNORECASE),  # rm -rf /
            re.compile(r"mkfs|dd\s+if=|format\s+[a-z]:", re.IGNORECASE),
            re.compile(r"shutdown|reboot|halt|poweroff", re.IGNORECASE),
            re.compile(r":\(\)\s*\{.*\};:", re.IGNORECASE),  # fork bomb
            re.compile(r"curl\s+.*\|\s*(sh|bash)|wget\s+.*\|\s*(sh|bash)", re.IGNORECASE),
            re.compile(r"nc\s+.*-e|ncat\s+.*-e", re.IGNORECASE),  # reverse shell
            re.compile(r"/dev/(tcp|udp)/", re.IGNORECASE),
        ]

        # 安全命令白名单（高置信度放行）
        self._safe_patterns = [
            re.compile(r"^(ls|ll|pwd|whoami|hostname|uname|df|free|uptime|date)$", re.IGNORECASE),
            re.compile(r"^(cat|head|tail|grep|find|wc|echo|ping|ps)\s+[^\r\n|;&]*$", re.IGNORECASE),
            re.compile(r"^git\s+(status|log|diff|show|branch)$", re.IGNORECASE),
        ]

    def review(self, ctx: ReviewContext) -> ReviewResult:
        t0 = time.monotonic()
        if (invalid := self._invalid_context(ctx, "smart")) is not None:
            self._log_audit(ctx, invalid)
            return invalid
        cmd = ctx.command.strip()

        # 1. 黑名单检查（高置信度拒绝）
        for pattern in self._blacklist:
            if pattern.search(cmd):
                result = ReviewResult(
                    approved=False,
                    mode="smart",
                    reason=f"命中危险命令黑名单: {pattern.pattern}。如需执行请设置 allow_dangerous=True。",
                    risk_level="critical",
                    elapsed=time.monotonic() - t0,
                    plan_id=ctx.plan_id,
                )
                self._log_audit(ctx, result)
                return result

        # 2. 安全白名单（高置信度放行）
        for pattern in self._safe_patterns:
            if pattern.search(cmd):
                result = ReviewResult(
                    approved=True,
                    mode="smart",
                    reason=f"匹配安全命令白名单: {pattern.pattern}",
                    risk_level="low",
                    elapsed=time.monotonic() - t0,
                    plan_id=ctx.plan_id,
                )
                self._log_audit(ctx, result)
                return result

        # 3. 不确定 → 降级为人工审核
        _log.info("smart_review_fallback_to_manual", command=cmd[:100])
        manual_result = self._manual_reviewer.review(ctx)
        return ReviewResult(
            approved=manual_result.approved,
            mode="smart(manual)",
            reason=f"[智能审核→人工] {manual_result.reason}",
            risk_level=manual_result.risk_level,
            elapsed=time.monotonic() - t0,
            plan_id=ctx.plan_id,
        )


# ---------------------------------------------------------------------------
# 审核引擎配置
# ---------------------------------------------------------------------------

@dataclass
class ReviewConfig:
    """审核引擎配置。"""
    mode: ReviewMode = field(default_factory=ReviewMode.from_env)
    whitelist_file: Optional[Path] = None
    manual_timeout: int = 60

    def __post_init__(self) -> None:
        # 白名单文件路径
        if self.whitelist_file is None:
            default_path = Path.home() / ".ssh" / "mcp-ssh-whitelist.conf"
            env_path = os.getenv("SSH_REVIEW_WHITELIST_FILE")
            self.whitelist_file = Path(env_path) if env_path else default_path

        # 人工审核超时
        env_timeout = os.getenv("SSH_REVIEW_MANUAL_TIMEOUT")
        if env_timeout:
            try:
                self.manual_timeout = int(env_timeout)
            except ValueError:
                raise ValueError("SSH_REVIEW_MANUAL_TIMEOUT 必须是整数")
        if self.manual_timeout <= 0:
            raise ValueError("manual_timeout 必须大于 0")


# ---------------------------------------------------------------------------
# 审核引擎（单例）
# ---------------------------------------------------------------------------

class ReviewEngine:
    """审核引擎：工厂 + 单例 + 动态切换。"""

    _instance: Optional["ReviewEngine"] = None
    _lock = threading.Lock()

    def __init__(self) -> None:
        self.config = ReviewConfig()
        self._reviewers: dict[ReviewMode, BaseReviewer] = {}
        self._init_reviewers()

    def _init_reviewers(self) -> None:
        """初始化所有审核器。"""
        self._reviewers = {
            ReviewMode.OFF: OffReviewer(self.config),
            ReviewMode.WHITELIST: WhitelistReviewer(self.config),
            ReviewMode.MANUAL: ManualReviewer(self.config),
            ReviewMode.SMART: SmartReviewer(self.config),
        }

    @classmethod
    def get_instance(cls) -> "ReviewEngine":
        """获取单例实例。"""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    def review(self, ctx: ReviewContext) -> ReviewResult:
        """执行审核。"""
        reviewer = self._reviewers[self.config.mode]
        return reviewer.review(ctx)

    def set_mode(self, mode: ReviewMode | str) -> tuple[bool, str]:
        """切换审核模式（无授权门槛，由默认状态决定）。"""
        if isinstance(mode, str):
            try:
                mode = ReviewMode(mode.lower().strip())
            except ValueError:
                _log.warning(
                    "review_mode_switch_rejected",
                    mode=mode,
                    reason="无效的审核模式",
                )
                return False, f"无效的审核模式: {mode}。可选: off, whitelist, manual, smart"

        old_mode = self.config.mode
        self.config.mode = mode
        _log.info("review_mode_changed", old=old_mode.value, new=mode.value)
        return True, f"审核模式已从 {old_mode.value} 切换为 {mode.value}"

    def get_mode(self) -> str:
        """获取当前审核模式。"""
        return self.config.mode.value

    def get_status(self) -> dict:
        """获取审核引擎状态。"""
        return {
            "mode": self.config.mode.value,
            "whitelist_file": str(self.config.whitelist_file),
            "whitelist_exists": self.config.whitelist_file.exists() if self.config.whitelist_file else False,
            "manual_timeout": self.config.manual_timeout,
        }


# ---------------------------------------------------------------------------
# 便捷函数
# ---------------------------------------------------------------------------

_engine: Optional[ReviewEngine] = None


def get_review_engine() -> ReviewEngine:
    """获取审核引擎单例。"""
    global _engine
    if _engine is None:
        _engine = ReviewEngine.get_instance()
    return _engine


def review_command(
    command: str,
    tool: str = "ssh_exec",
    host: str = "",
    path: str = "",
    allow_dangerous: bool = False,
) -> ReviewResult:
    """审核命令的便捷函数。"""
    ctx = ReviewContext(
        tool=tool,
        command=command,
        host=host,
        path=path,
        allow_dangerous=allow_dangerous,
    )
    return get_review_engine().review(ctx)
