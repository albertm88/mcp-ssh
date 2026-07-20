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
import re
import sys
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

from logger import get_logger

_log = get_logger()


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

@dataclass
class ReviewResult:
    """审核结果。"""
    approved: bool
    mode: str
    reason: str = ""
    risk_level: str = "unknown"  # low / medium / high / critical
    elapsed: float = 0.0

    def __bool__(self) -> bool:
        return self.approved


# ---------------------------------------------------------------------------
# 审核上下文
# ---------------------------------------------------------------------------

@dataclass
class ReviewContext:
    """审核上下文信息。"""
    tool: str  # 调用的工具名，如 ssh_exec / ssh_upload
    command: str = ""  # 要执行的命令
    host: str = ""  # 目标主机
    path: str = ""  # 涉及的路径（文件操作时）
    allow_dangerous: bool = False  # 是否显式允许危险操作


# ---------------------------------------------------------------------------
# 基础审核器
# ---------------------------------------------------------------------------

class BaseReviewer:
    """审核器基类。"""

    def __init__(self, config: "ReviewConfig") -> None:
        self.config = config

    def review(self, ctx: ReviewContext) -> ReviewResult:
        raise NotImplementedError

    def _log_audit(self, ctx: ReviewContext, result: ReviewResult) -> None:
        """记录审计日志。"""
        _log.info(
            "review_audit",
            tool=ctx.tool,
            mode=result.mode,
            approved=result.approved,
            risk_level=result.risk_level,
            reason=result.reason,
            command=ctx.command[:200] if ctx.command else "",
            host=ctx.host,
            path=ctx.path,
            elapsed=round(result.elapsed, 3),
        )


# ---------------------------------------------------------------------------
# 关闭审核
# ---------------------------------------------------------------------------

class OffReviewer(BaseReviewer):
    """关闭审核：所有操作直接放行。"""

    def review(self, ctx: ReviewContext) -> ReviewResult:
        t0 = time.monotonic()
        result = ReviewResult(
            approved=True,
            mode="off",
            reason="审核已关闭，直接放行",
            risk_level="unknown",
            elapsed=time.monotonic() - t0,
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
        cmd = ctx.command.strip()

        # 检查是否匹配白名单
        for pattern in self._whitelist:
            if pattern.search(cmd):
                result = ReviewResult(
                    approved=True,
                    mode="whitelist",
                    reason=f"匹配白名单规则: {pattern.pattern}",
                    risk_level="low",
                    elapsed=time.monotonic() - t0,
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

        # 如果显式设置了 allow_dangerous，跳过人工确认
        if ctx.allow_dangerous:
            result = ReviewResult(
                approved=True,
                mode="manual",
                reason="显式 allow_dangerous=True，跳过人工确认",
                risk_level="high",
                elapsed=time.monotonic() - t0,
            )
            self._log_audit(ctx, result)
            return result

        # 打印待审核命令
        self._print_review_banner(ctx)

        # 等待人工确认
        approved = self._wait_for_confirmation(ctx)

        result = ReviewResult(
            approved=approved,
            mode="manual",
            reason="人工批准" if approved else "人工拒绝或超时",
            risk_level="medium" if approved else "high",
            elapsed=time.monotonic() - t0,
        )
        self._log_audit(ctx, result)
        return result

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
  路径:     {ctx.path or 'N/A'}
  危险标记: {ctx.allow_dangerous}
{'='*70}
请在 {self.config.manual_timeout}s 内确认：
  [y/yes] 批准执行
  [n/no]  拒绝执行（默认）
{'='*70}
""".strip()
        self._safe_print(banner, file=sys.stderr, flush=True)

    def _wait_for_confirmation(self, ctx: ReviewContext) -> bool:
        """等待人工确认，支持超时。"""
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
            re.compile(r"^(cat|head|tail|grep|find|wc|echo|ping|ps)\s+[^|;&]*$", re.IGNORECASE),
            re.compile(r"^git\s+(status|log|diff|show|branch)$", re.IGNORECASE),
        ]

    def review(self, ctx: ReviewContext) -> ReviewResult:
        t0 = time.monotonic()
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
                )
                self._log_audit(ctx, result)
                return result

        # 3. 不确定 → 降级为人工审核
        _log.info("smart_review_fallback_to_manual", command=cmd[:100])
        manual_result = self._manual_reviewer.review(ctx)
        manual_result.mode = "smart(manual)"
        manual_result.reason = f"[智能审核→人工] {manual_result.reason}"
        return manual_result


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
                pass


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
        """动态切换审核模式。"""
        if isinstance(mode, str):
            try:
                mode = ReviewMode(mode.lower().strip())
            except ValueError:
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
