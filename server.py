"""SSH control MCP server.

复用本地 ~/.ssh/config 的主机别名与凭据；密钥优先，密码兜底。
密码通过环境变量 SSH_PASS_<HOST> 提供（点/横线转下划线，全大写），
或 SSH_PASS 作为全局兜底。密钥不会落配置文件。

跨平台支持：Windows/Linux，自动适配编码、路径、shell 差异。
安全防护：命令注入检测、危险命令拦截、输出编码自动识别、严格 host-key。
"""
from __future__ import annotations

import functools
import hashlib
import json
import os
import pathlib
import platform
import re
import shlex
import socket
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Literal

import paramiko
from charset_normalizer import from_bytes
from mcp.server.fastmcp import FastMCP
from paramiko import SSHConfig

from host_keys import (
    HostKeyError,
    apply_host_key_policy,
    host_key_mismatch_message,
    is_host_key_failure,
)
from logger import get_logger
from results import (
    ERROR_AUTH_FAILED,
    ERROR_CHECKSUM_MISMATCH,
    ERROR_CONNECT_TIMEOUT,
    ERROR_CONNECTION_LOST,
    ERROR_EXEC_TIMEOUT,
    ERROR_HOST_KEY_MISMATCH,
    ERROR_INVALID_ARGUMENT,
    ERROR_LOCAL_IO_ERROR,
    ERROR_OUTPUT_LIMIT,
    ERROR_REMOTE_EXIT_NONZERO,
    ERROR_REMOTE_IO_ERROR,
    ERROR_RESOURCE_LIMIT,
    STATUS_FAILED,
    STATUS_PARTIAL,
    STATUS_SUCCEEDED,
    STATUS_TIMED_OUT,
    make_failure,
    make_rejected,
    make_success,
)
from review import (
    ReviewContext,
    ReviewResult,
    build_environment_plan,
    get_review_engine,
)

mcp = FastMCP("ssh")
_log = get_logger()
_review_engine = get_review_engine()

# 跨平台 SSH 目录适配
if platform.system() == "Windows":
    _SSH_DIR = pathlib.Path(os.environ.get("USERPROFILE", pathlib.Path.home())) / ".ssh"
else:
    _SSH_DIR = pathlib.Path.home() / ".ssh"
_DEFAULT_KEY_NAMES = ("id_ed25519", "id_ecdsa", "id_rsa", "id_dsa")

# 危险命令拦截列表（防止误操作）
_DANGEROUS_COMMANDS = re.compile(
    r"^\s*(rm\s+(-rf?|--recursive)\s+/(?!tmp|var/tmp)|mkfs|dd\s+if=|format\s+[a-z]:|shutdown|reboot|halt|poweroff|:\(\)\s*\{.*\};:|fork\s*bomb)",
    re.IGNORECASE,
)
# 命令注入特征检测（排除合法的 && || 管道操作，只检测恶意特征）
_INJECTION_PATTERNS = re.compile(
    r";\s*(rm|wget|curl|nc|ncat|bash|sh|chmod|chown|passwd|useradd)|/dev/(tcp|udp)/|wget\s+https?://.*\|\s*(sh|bash)|curl\s+https?://.*\|\s*(sh|bash)|nc\s+.*-e|ncat\s+.*-e|\|\s*(sh|bash|zsh|python|perl)\s*$",
    re.IGNORECASE,
)
# 敏感文件路径保护
_SENSITIVE_PATHS = re.compile(
    r"/etc/(passwd|shadow|ssh/sshd_config|sudoers)|/root/\.ssh/|~/.ssh/id_",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# 资源限制（off 模式也不能关闭）
# ---------------------------------------------------------------------------

_MAX_SINGLE_FILE_BYTES = 100 * 1024 * 1024  # 100 MiB
_MAX_DIR_FILES = 2000
_MAX_DIR_BYTES = 1024 * 1024 * 1024  # 1 GiB
_MAX_RECURSE_DEPTH = 32
_MAX_OUTPUT_BYTES = 1024 * 1024  # 1 MiB


class ResourceLimitError(Exception):
    """请求超过配置的资源上限，连接前失败关闭。"""


class ChecksumMismatchError(Exception):
    """传输校验失败（字节数或 SHA-256 不一致）。"""


class ReviewRejectedError(Exception):
    """审核拒绝，不执行任何 SSH/SFTP 副作用。"""


def _review_summary(result: ReviewResult) -> dict:
    return {
        "mode": result.mode,
        "decision": "approved" if result.approved else "rejected",
        "risk": result.risk_level,
        "reason": result.reason,
        "plan_id": result.plan_id,
    }


def _sha256_stream(fileobj) -> str:
    """流式计算 SHA-256，峰值内存 O(chunk)。"""
    h = hashlib.sha256()
    while True:
        chunk = fileobj.read(1 << 16)
        if not chunk:
            break
        h.update(chunk)
    return h.hexdigest()


def _sha256_local(path: pathlib.Path) -> str:
    with path.open("rb") as f:
        return _sha256_stream(f)


def _sha256_remote(sftp, remote: str) -> str:
    with sftp.open(remote, "rb") as f:
        return _sha256_stream(f)


def _reject_remote_traversal(remote_path: str) -> None:
    """拒绝包含 . / .. 路径组件的远端路径（Review 敏感路径绕过修复）。

    基于原始字符串按 / 拆分判断，避免 PurePosixPath 先规范化掉 "."
    导致 /etc/./shadow 这类绕过被漏检。在连接前失败关闭。
    """
    components = [c for c in remote_path.split("/") if c]
    if any(c in (".", "..") for c in components):
        raise ValueError(f"远端路径包含不受支持的 . / .. 组件：{remote_path}")


def _connect_failure_envelope(
    e: Exception, tool: str, host: str, review: dict | None = None,
) -> dict:
    """把 _connect 抛出的 HostKeyError / RuntimeError 映射为稳定错误 envelope。"""
    if isinstance(e, HostKeyError):
        return make_failure(
            ERROR_HOST_KEY_MISMATCH, str(e), tool=tool, host=host,
            review=review,
        ).to_dict()
    message = str(e)
    if "认证失败" in message:
        code = ERROR_AUTH_FAILED
    elif "身份文件不存在" in message:
        code = ERROR_INVALID_ARGUMENT
    elif "连接超时" in message or "timeout" in message.lower():
        code = ERROR_CONNECT_TIMEOUT
    else:
        code = ERROR_CONNECTION_LOST
    return make_failure(
        code, message, tool=tool, host=host, review=review,
    ).to_dict()


def _tool_boundary(tool_name: str):
    """行为边界钩子：统一把工具抛出的未捕获异常映射为稳定错误 envelope。

    保证所有 MCP 工具 100% 返回 ResultEnvelope——即使某个工具内部遗漏了
    某个错误分支，也不会以裸异常逃逸出 MCP 边界。由 functools.wraps 保留
    原函数签名与 FastMCP schema。
    """

    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            t0 = time.monotonic()
            try:
                return fn(*args, **kwargs)
            except ReviewRejectedError as e:
                return make_rejected(str(e), tool=tool_name).to_dict()
            except HostKeyError as e:
                _log.error("tool_boundary_host_key", tool=tool_name, error=str(e))
                return _connect_failure_envelope(e, tool_name, "", review=None)
            except ResourceLimitError as e:
                _log.error("tool_boundary_resource_limit", tool=tool_name, error=str(e))
                return make_failure(
                    ERROR_RESOURCE_LIMIT, str(e), tool=tool_name,
                ).to_dict()
            except ChecksumMismatchError as e:
                _log.error("tool_boundary_checksum", tool=tool_name, error=str(e))
                return make_failure(
                    ERROR_CHECKSUM_MISMATCH, str(e), tool=tool_name,
                ).to_dict()
            except TimeoutError as e:
                _log.error("tool_boundary_timeout", tool=tool_name, error=str(e))
                return make_failure(
                    ERROR_EXEC_TIMEOUT, str(e), tool=tool_name,
                    status=STATUS_TIMED_OUT,
                ).to_dict()
            except paramiko.AuthenticationException as e:
                _log.error("tool_boundary_auth", tool=tool_name, error=str(e))
                return make_failure(
                    ERROR_AUTH_FAILED, str(e), tool=tool_name,
                ).to_dict()
            except OSError as e:
                _log.error("tool_boundary_io", tool=tool_name, error=str(e))
                return make_failure(
                    ERROR_CONNECTION_LOST, str(e), tool=tool_name,
                ).to_dict()
            except RuntimeError as e:
                _log.error("tool_boundary_runtime", tool=tool_name, error=str(e))
                return _connect_failure_envelope(e, tool_name, "", review=None)
            except Exception as e:
                _log.error(
                    "tool_boundary_unhandled", tool=tool_name,
                    error=str(e), elapsed=round(time.monotonic() - t0, 3),
                )
                return make_failure(
                    ERROR_REMOTE_IO_ERROR, str(e), tool=tool_name,
                ).to_dict()

        return wrapper

    return decorator


def _load_ssh_config() -> SSHConfig:
    cfg = SSHConfig()
    cfg_path = _SSH_DIR / "config"
    if cfg_path.exists():
        with cfg_path.open(encoding="utf-8") as f:
            cfg.parse(f)
    return cfg


def _password_env_var(host: str) -> str | None:
    key = f"SSH_PASS_{host.upper().replace('.', '_').replace('-', '_')}"
    return os.getenv(key) or os.getenv("SSH_PASS")


def _connect(host: str, timeout: float = 10.0) -> paramiko.SSHClient:
    # 支持 user@host 写法
    user_from_at: str | None = None
    if "@" in host:
        user_from_at, _, host = host.partition("@")

    cfg = _load_ssh_config()
    conf = cfg.lookup(host)
    hostname = conf.get("hostname", host)
    username = (
        conf.get("user")
        or user_from_at
        or os.getenv("USERNAME")
        or os.getenv("USER")
    )
    port = int(conf.get("port", 22))

    # ---- 快速预检：TCP 端口是否可达（跨平台错误处理） ----
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(min(timeout, 5.0))
    try:
        sock.connect((hostname, port))
        _log.debug("tcp_probe_ok", host=host, hostname=hostname, port=port)
    except TimeoutError:
        _log.warning("tcp_probe_timeout", host=host, hostname=hostname, port=port, timeout=timeout)
        raise RuntimeError(
            f"主机不可达：{hostname}:{port} 连接超时（{timeout}s），"
            f"请检查 IP/端口是否正确、主机是否在线、防火墙是否放行。"
        )
    except OSError as e:
        err_msg = str(e)
        if e.errno in (10060, 10061, 110, 111, 60, 61):
            err_type = "连接被拒绝" if e.errno in (10061, 111, 61) else "连接超时"
            _log.warning("tcp_probe_refused", host=host, hostname=hostname, port=port, error=err_msg, errno=e.errno)
            raise RuntimeError(
                f"主机不可达：{hostname}:{port} {err_type} — {err_msg}。"
                f"请确认 SSH 服务是否启动、端口是否正确、防火墙是否放行。"
            )
        _log.warning("tcp_probe_error", host=host, hostname=hostname, port=port, error=err_msg, errno=e.errno)
        raise RuntimeError(
            f"主机不可达：{hostname}:{port} 网络错误 — {err_msg}。"
            f"请确认主机在线且端口开放。"
        )
    finally:
        sock.close()

    client = paramiko.SSHClient()
    # 严格 host-key 策略：未知/错误指纹在认证前失败关闭（Review P1 #2）
    try:
        apply_host_key_policy(client, hostname, port)
    except RuntimeError as e:
        _log.error("ssh_host_key_mismatch", host=host, hostname=hostname, port=port, error=str(e))
        raise HostKeyError(str(e), hostname=hostname, port=port) from e

    # 1) 密钥：config 里的 IdentityFile + 默认密钥 + ssh-agent
    identity_files: list[str] = []
    ident = conf.get("identityfile")
    if ident:
        identity_files.extend(ident if isinstance(ident, list) else [ident])
    for name in _DEFAULT_KEY_NAMES:
        p = _SSH_DIR / name
        if p.exists() and str(p) not in identity_files:
            identity_files.append(str(p))

    # 显式配置的身份文件缺失：在认证前给出明确诊断，不裸抛 FileNotFoundError
    for key_path in identity_files:
        if not pathlib.Path(key_path).expanduser().exists():
            raise RuntimeError(
                f"SSH 身份文件不存在：{key_path}。请检查 ~/.ssh/config 的 "
                f"IdentityFile 或使用默认密钥（~/.ssh/id_ed25519 等）。"
            )

    last_err: Exception | None = None
    for key_path in identity_files:
        try:
            client.connect(
                hostname, port=port, username=username,
                key_filename=key_path, timeout=timeout,
                look_for_keys=False, allow_agent=True,
            )
            _log.info("ssh_connected", host=host, hostname=hostname, port=port,
                       username=username, auth="key", key=os.path.basename(key_path))
            return client
        except paramiko.BadHostKeyException as e:
            _log.error("ssh_host_key_mismatch", host=host, hostname=hostname, port=port, error=str(e))
            raise HostKeyError(
                host_key_mismatch_message(hostname, port, e),
                hostname=hostname, port=port,
            ) from e
        except paramiko.SSHException as e:
            if is_host_key_failure(e):
                _log.error("ssh_host_key_mismatch", host=host, hostname=hostname, port=port, error=str(e))
                raise HostKeyError(
                    host_key_mismatch_message(hostname, port, e),
                    hostname=hostname, port=port,
                ) from e
            _log.debug("key_auth_failed", host=host, key=os.path.basename(key_path), error=str(e))
            last_err = e
            continue

    # 2) 密码：环境变量
    pwd = _password_env_var(host)
    if pwd:
        try:
            client.connect(
                hostname, port=port, username=username,
                password=pwd, timeout=timeout,
                look_for_keys=False, allow_agent=False,
            )
            _log.info("ssh_connected", host=host, hostname=hostname, port=port,
                       username=username, auth="password")
            return client
        except paramiko.BadHostKeyException as e:
            _log.error("ssh_host_key_mismatch", host=host, hostname=hostname, port=port, error=str(e))
            raise HostKeyError(
                host_key_mismatch_message(hostname, port, e),
                hostname=hostname, port=port,
            ) from e
        except paramiko.SSHException as e:
            if is_host_key_failure(e):
                _log.error("ssh_host_key_mismatch", host=host, hostname=hostname, port=port, error=str(e))
                raise HostKeyError(
                    host_key_mismatch_message(hostname, port, e),
                    hostname=hostname, port=port,
                ) from e
            if isinstance(e, paramiko.AuthenticationException):
                _log.warning("auth_failed", host=host, hostname=hostname, port=port,
                              username=username, reason="bad_password")
                # 故意用 RuntimeError 统一错误通道（非类型错误语义）
                raise RuntimeError(  # noqa: TRY004
                    f"认证失败：{username}@{hostname}:{port} — 密码错误。"
                    f"请检查环境变量 SSH_PASS_{host.upper().replace('.', '_').replace('-', '_')}。"
                )
            _log.debug("password_auth_error", host=host, error=str(e))
            last_err = e

    _log.error("connect_failed", host=host, hostname=hostname, port=port,
                username=username, last_error=str(last_err))
    raise RuntimeError(
        f"无法连接 {host}（{username}@{hostname}:{port}）："
        f"无可用密钥/密码。最后错误：{last_err}"
    )


def _decode_output(raw: bytes) -> str:
    """自动检测输出编码，解决跨平台/跨语言编码错乱问题。"""
    if not raw:
        return ""
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        pass
    for enc in ("gbk", "cp936", "gb2312", "big5"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    try:
        result = from_bytes(raw).best()
        if result:
            return str(result)
    except Exception:  # noqa: S110 — 编码检测失败回退 UTF-8，容错设计
        pass
    return raw.decode("utf-8", errors="replace")


def _read_channel(channel: paramiko.Channel, deadline: float) -> dict:
    """Read channel output until exit or an absolute monotonic deadline.

    Returns {"text": str, "truncated": bool}. Output is capped at
    _MAX_OUTPUT_BYTES; beyond that the text is truncated and truncated=True
    (quota is enforced in every review mode).
    """
    chunks: list[bytes] = []
    total = 0
    truncated = False

    def _append(data: bytes) -> None:
        nonlocal total, truncated
        if truncated:
            return
        remaining = _MAX_OUTPUT_BYTES - total
        if len(data) > remaining:
            if remaining > 0:
                chunks.append(data[:remaining])
            total = _MAX_OUTPUT_BYTES
            truncated = True
        else:
            chunks.append(data)
            total += len(data)

    while not channel.exit_status_ready():
        if channel.recv_ready():
            _append(channel.recv(65536))
        else:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("远程命令执行超过 timeout deadline")
            channel.settimeout(min(remaining, 0.2))
            time.sleep(min(remaining, 0.05))
    while channel.recv_ready():
        if time.monotonic() >= deadline:
            raise TimeoutError("远程命令输出收尾超过 timeout deadline")
        _append(channel.recv(65536))
    return {"text": _decode_output(b"".join(chunks)), "truncated": truncated}


def _review_context(ctx: ReviewContext) -> ReviewResult:
    """Review the exact operation context before any remote side effect."""
    result = _review_engine.review(ctx)
    if not result.approved:
        raise ReviewRejectedError(f"审核拒绝 [{result.mode}]: {result.reason}")
    return result


def _get_mcp_ctx() -> Any:
    """获取当前请求的 MCP Context（manual 弹框用）；非请求上下文时返回 None。"""
    try:
        ctx = mcp.get_context()
        sess = getattr(ctx, "session", None)
        cp = getattr(sess, "client_params", None) if sess is not None else None
        caps = getattr(cp, "capabilities", None) if cp is not None else None
        _log.info("mcp_ctx_probe",
                  has_session=sess is not None,
                  has_client_params=cp is not None,
                  has_elicitation=(caps is not None and getattr(caps, "elicitation", None) is not None))
        return ctx
    except Exception as e:
        _log.warning("mcp_ctx_probe_error", error=str(e))
        return None


def _validate_command(
    command: str,
    allow_dangerous: bool = False,
    host: str = "",
    tool: str = "ssh_exec",
    shell: str | None = None,
    environment: dict[str, str] | None = None,
    ctx: Any = None,
) -> tuple[ReviewContext, ReviewResult]:
    """命令安全校验：委托审核引擎进行多模式审核。

    防御纵深（defense-in-depth）：即使审核模式为 off，
    命令注入特征与危险命令拦截仍然生效（与资源限制同级，不可绕过）；
    危险命令在 `allow_dangerous=True` 时豁免，注入特征无豁免。
    """
    if not command.strip():
        raise ValueError("命令不能为空")

    if len(command) > 10000:
        _log.warning("command_too_long", length=len(command))
        raise RuntimeError("命令长度超过限制（最大10000字符）")

    if not allow_dangerous and _DANGEROUS_COMMANDS.search(command):
        _log.warning("dangerous_command_blocked", command=command[:200])
        raise RuntimeError("命令命中危险命令拦截列表，如需执行请设置 allow_dangerous=True")

    if _INJECTION_PATTERNS.search(command):
        _log.warning("command_injection_blocked", command=command[:200])
        raise RuntimeError("命令命中注入特征检测，已拒绝执行")

    _, environment_names, environment_digest = build_environment_plan(environment)
    ctx_obj = ReviewContext(
        tool=tool,
        command=command,
        host=host,
        allow_dangerous=allow_dangerous,
        shell=shell,
        environment=environment_names,
        environment_digest=environment_digest,
        mcp_ctx=ctx,
    )
    result = _review_context(ctx_obj)
    _log.debug("command_validated", command=command[:500], mode=_review_engine.get_mode())
    return ctx_obj, result


def _normalize_command(command: str, shell: str | None = None) -> str:
    """跨平台命令标准化：自动适配不同系统的 shell 和换行符。"""
    command = command.replace("\r\n", "\n").replace("\r", "\n")

    if shell is not None:
        shell_lower = shell.lower()
        if shell_lower in ("cmd", "cmd.exe"):
            command = f"cmd /c {command}"
        elif shell_lower in ("powershell", "pwsh", "ps"):
            import base64

            encoded = base64.b64encode(command.encode("utf-16-le")).decode("ascii")
            command = f"powershell -NoProfile -EncodedCommand {encoded}"
        elif shell_lower in ("bash", "sh", "zsh"):
            command = f"{shell} -c {shlex.quote(command)}"
        else:
            _redacted = re.sub(r"(export\s+[A-Za-z_][A-Za-z0-9_]*=)[^;]+", r"\1***", command)
            _log.warning("unknown_shell", shell=shell, command=_redacted[:100])
    else:
        cmd_lower = command.lower()
        is_windows_cmd = (
            any(cmd_lower.startswith(p) for p in ("ipconfig", "netstat", "tasklist", "systeminfo", "ver", "vol"))
            or ("dir " in cmd_lower and "\\" in command)
            or (len(command) > 2 and command[1] == ":" and command[2] == "\\")
        )
        if is_windows_cmd:
            command = f"cmd /c {command}"
            _redacted = re.sub(r"(export\s+[A-Za-z_][A-Za-z0-9_]*=)[^;]+", r"\1***", command)
            _log.debug("windows_cmd_detected", original=_redacted[:100])

    return command


# ---------------------------------------------------------------------------
# SFTP 可靠原子传输 helpers
# ---------------------------------------------------------------------------


def _sftp_tmp_name(target: str) -> str:
    """生成目标同目录的不可预测临时文件名。"""
    parent = pathlib.PurePosixPath(target).parent
    name = pathlib.PurePosixPath(target).name
    tmp = f".{name}.{uuid.uuid4().hex}.tmp"
    if str(parent) in ("", "."):
        return tmp
    return f"{parent}/{tmp}"


def _sftp_put_atomic(
    sftp: paramiko.SFTPClient,
    local: pathlib.Path,
    remote: str,
    overwrite: bool,
) -> dict:
    """目标同目录临时名 → 流式写入 → 字节/sha256 校验 → 原子替换。"""
    if not overwrite:
        try:
            sftp.stat(remote)
            raise FileExistsError(f"远端目标已存在：{remote}（overwrite=False）")
        except FileNotFoundError:
            pass
    tmp_remote = _sftp_tmp_name(remote)
    local_size = local.stat().st_size
    try:
        with local.open("rb") as f:
            sftp.putfo(f, tmp_remote, confirm=True)
        remote_stat = sftp.stat(tmp_remote)
        if remote_stat.st_size != local_size:
            raise ChecksumMismatchError(
                f"字节数不一致：local={local_size} remote={remote_stat.st_size}"
            )
        local_digest = _sha256_local(local)
        remote_digest = _sha256_remote(sftp, tmp_remote)
        if local_digest != remote_digest:
            raise ChecksumMismatchError("SHA-256 校验不一致")
        try:
            sftp.posix_rename(tmp_remote, remote)
        except OSError:
            sftp.rename(tmp_remote, remote)
        return {
            "bytes": local_size,
            "sha256": local_digest,
            "tmp_cleaned": False,
            "atomic": True,
        }
    except Exception:
        try:
            sftp.remove(tmp_remote)
        except OSError:
            _log.warning("sftp_tmp_cleanup_failed", remote=tmp_remote)
        raise


def _sftp_get_atomic(
    sftp: paramiko.SFTPClient,
    remote: str,
    local: pathlib.Path,
) -> dict:
    """本地同目录临时名 → 远端 size/可选 checksum 校验 → 原子替换。"""
    remote_stat = sftp.stat(remote)
    tmp_local = local.parent / f".{local.name}.{uuid.uuid4().hex}.tmp"
    try:
        sftp.get(remote, str(tmp_local))
        local_size = tmp_local.stat().st_size
        if local_size != remote_stat.st_size:
            raise ChecksumMismatchError(
                f"字节数不一致：remote={remote_stat.st_size} local={local_size}"
            )
        digest = _sha256_local(tmp_local)
        tmp_local.replace(local)
        return {
            "bytes": local_size,
            "sha256": digest,
            "atomic": True,
        }
    except Exception:
        try:
            tmp_local.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _bounded_walk(
    root,
    *,
    sftp=None,
    max_files: int = _MAX_DIR_FILES,
    max_bytes: int = _MAX_DIR_BYTES,
    max_depth: int = _MAX_RECURSE_DEPTH,
) -> list[dict]:
    """有界递归遍历：拒绝软链接逃逸、超过文件数/总字节/深度。

    传入 `sftp`（paramiko.SFTPClient）时走 SFTP `listdir_attr`；
    否则 `root` 视为本地 pathlib.Path，走 `iterdir`。

    返回条目统一为 `{"path", "size", "is_dir"}` 字典。
    """
    entries: list[dict] = []
    total_files = 0
    total_bytes = 0
    is_sftp = sftp is not None

    def _walk(path, depth: int) -> None:
        nonlocal total_files, total_bytes
        if depth > max_depth:
            raise ResourceLimitError(f"递归深度超过限制 {max_depth}")
        try:
            if is_sftp:
                attrs = sftp.listdir_attr(path)
                files = [attr.filename for attr in attrs]
            else:
                files = sorted(path.iterdir(), key=lambda p: p.name)
        except (FileNotFoundError, OSError):
            return
        if not is_sftp and total_files + len(files) > max_files:
            raise ResourceLimitError(
                f"目录 {path} 条目数超过剩余配额（{max_files - total_files}）"
            )
        for idx, child in enumerate(files):
            if is_sftp:
                attr = attrs[idx]
                mode = attr.st_mode
                if mode & 0o170000 == 0o120000:
                    raise ResourceLimitError(f"拒绝软链接逃逸：{path}/{attr.filename}")
                child_path = (
                    f"{path}/{attr.filename}"
                    if str(path) not in ("", "/")
                    else f"{path}{attr.filename}"
                )
                is_dir = bool(mode & 0o40000)
                is_file = bool(mode & 0o100000)
                size = attr.st_size
            else:
                if child.is_symlink():
                    raise ResourceLimitError(f"拒绝软链接逃逸：{child}")
                is_dir = child.is_dir()
                is_file = child.is_file()
                child_path = child
                size = child.stat().st_size if is_file else 0
            if is_dir:
                total_files += 1
                if total_files > max_files:
                    raise ResourceLimitError(f"文件数超过限制 {max_files}")
                entries.append({"path": child_path, "size": 0, "is_dir": True})
                _walk(child_path, depth + 1)
            elif is_file:
                total_files += 1
                total_bytes += size
                if total_files > max_files:
                    raise ResourceLimitError(f"文件数超过限制 {max_files}")
                if total_bytes > max_bytes:
                    raise ResourceLimitError(f"总字节超过限制 {max_bytes}")
                entries.append({"path": child_path, "size": size, "is_dir": False})

    _walk(root, 0)
    return entries


# 11 个 MCP 工具（全部经 _tool_boundary 钩子统一错误边界）
# ---------------------------------------------------------------------------


@mcp.tool()
@_tool_boundary("ssh_exec")
def ssh_exec(
    host: str,
    command: str,
    timeout: float = 30,
    shell: str | None = None,
    allow_dangerous: bool = False,
    environment: dict[str, str] | None = None,
) -> dict:
    """在远程主机上执行一条 shell 命令并返回结果。"""
    request_id = uuid.uuid4().hex
    if timeout <= 0:
        return make_failure(
            ERROR_INVALID_ARGUMENT, "timeout 必须大于 0",
            tool="ssh_exec", host=host, request_id=request_id,
        ).to_dict()
    normalized_environment, _, _ = build_environment_plan(environment)
    try:
        mcp_ctx = None
        try:
            mcp_ctx = mcp.get_context()
        except Exception:
            mcp_ctx = None
        plan_ctx, review_result = _validate_command(
            command,
            allow_dangerous=allow_dangerous,
            host=host,
            tool="ssh_exec",
            shell=shell,
            environment=normalized_environment,
            ctx=mcp_ctx,
        )
    except ReviewRejectedError as e:
        return make_rejected(
            str(e), tool="ssh_exec", host=host, request_id=request_id,
        ).to_dict()
    except (ValueError, RuntimeError) as e:
        return make_failure(
            ERROR_INVALID_ARGUMENT, str(e),
            tool="ssh_exec", host=host, request_id=request_id,
        ).to_dict()

    command = _normalize_command(command, shell=shell)
    if normalized_environment:
        env_prefix = " ".join(
            f"export {k}={shlex.quote(v)};"
            for k, v in normalized_environment.items()
        )
        command = f"{env_prefix} {command}"

    t0 = time.monotonic()
    deadline = t0 + timeout
    client = None
    try:
        connect_budget = max(0.1, deadline - time.monotonic())
        client = _connect(host, timeout=connect_budget)
        command_budget = max(0.1, deadline - time.monotonic())
        _stdin, stdout, stderr = client.exec_command(
            command,
            timeout=command_budget,
            get_pty=True,
        )
        out_res = _read_channel(stdout.channel, deadline)
        err_res = _read_channel(stderr.channel, deadline)
        if not stdout.channel.exit_status_ready():
            raise TimeoutError("远程命令未在 timeout deadline 内退出")
        code = stdout.channel.recv_exit_status()
    except HostKeyError as e:
        _log.error(
            "ssh_host_key_mismatch", host=host, command_length=len(command),
            plan_id=plan_ctx.plan_id, elapsed=round(time.monotonic() - t0, 3),
            error=str(e),
        )
        return make_failure(
            ERROR_HOST_KEY_MISMATCH, str(e), tool="ssh_exec", host=host,
            request_id=request_id, review=_review_summary(review_result),
            duration_ms=int((time.monotonic() - t0) * 1000),
        ).to_dict()
    except TimeoutError as e:
        _log.error(
            "ssh_exec_timed_out", host=host, command_length=len(command),
            plan_id=plan_ctx.plan_id, elapsed=round(time.monotonic() - t0, 3),
            error=str(e),
        )
        return make_failure(
            ERROR_EXEC_TIMEOUT, str(e), tool="ssh_exec", host=host,
            status=STATUS_TIMED_OUT, request_id=request_id,
            review=_review_summary(review_result),
            duration_ms=int((time.monotonic() - t0) * 1000),
        ).to_dict()
    except paramiko.AuthenticationException as e:
        _log.error(
            "ssh_exec_auth_failed", host=host, command_length=len(command),
            plan_id=plan_ctx.plan_id, elapsed=round(time.monotonic() - t0, 3),
            error=str(e),
        )
        return make_failure(
            ERROR_AUTH_FAILED, str(e), tool="ssh_exec", host=host,
            request_id=request_id, review=_review_summary(review_result),
            duration_ms=int((time.monotonic() - t0) * 1000),
        ).to_dict()
    except OSError as e:
        _log.error(
            "ssh_exec_connection_lost", host=host, command_length=len(command),
            plan_id=plan_ctx.plan_id, elapsed=round(time.monotonic() - t0, 3),
            error=str(e),
        )
        return make_failure(
            ERROR_CONNECTION_LOST, str(e), tool="ssh_exec", host=host,
            request_id=request_id, review=_review_summary(review_result),
            duration_ms=int((time.monotonic() - t0) * 1000),
        ).to_dict()
    except RuntimeError as e:
        _log.error(
            "ssh_exec_connect_failed", host=host, command_length=len(command),
            plan_id=plan_ctx.plan_id, elapsed=round(time.monotonic() - t0, 3),
            error=str(e),
        )
        message = str(e)
        if "认证失败" in message:
            code, status = ERROR_AUTH_FAILED, STATUS_FAILED
        elif "身份文件不存在" in message:
            code, status = ERROR_INVALID_ARGUMENT, STATUS_FAILED
        elif "连接超时" in message or "timeout" in message.lower():
            code, status = ERROR_CONNECT_TIMEOUT, STATUS_TIMED_OUT
        else:
            code, status = ERROR_CONNECTION_LOST, STATUS_FAILED
        return make_failure(
            code, message, tool="ssh_exec", host=host, status=status,
            request_id=request_id, review=_review_summary(review_result),
            duration_ms=int((time.monotonic() - t0) * 1000),
        ).to_dict()
    finally:
        if client is not None:
            client.close()

    elapsed = time.monotonic() - t0
    out = out_res["text"]
    err = err_res["text"]
    truncated = out_res["truncated"] or err_res["truncated"]
    _redacted = re.sub(r"(export\s+[A-Za-z_][A-Za-z0-9_]*=)[^;]+", r"\1***", command)
    _log.info("ssh_exec_done", host=host, command=_redacted[:120],
               exit_code=code, elapsed=round(elapsed, 3),
               out_len=len(out), err_len=len(err), shell=shell)

    parts = [f"[exit_code] {code}"]
    if out:
        parts.append(f"[stdout]\n{out.rstrip()}")
    if err:
        parts.append(f"[stderr]\n{err.rstrip()}")
    text = "\n".join(parts)
    if truncated:
        return make_failure(
            ERROR_OUTPUT_LIMIT, f"远程命令输出超过配额（最大{_MAX_OUTPUT_BYTES}字节）",
            tool="ssh_exec", host=host, request_id=request_id,
            review=_review_summary(review_result),
            duration_ms=int(elapsed * 1000),
            data={
                "exit_code": code,
                "stdout": out,
                "stderr": err,
                "timed_out": False,
                "truncated": True,
            },
        ).to_dict()
    if code != 0:
        return make_failure(
            ERROR_REMOTE_EXIT_NONZERO,
            f"远程命令退出码非零：{code}",
            tool="ssh_exec", host=host, request_id=request_id,
            review=_review_summary(review_result),
            duration_ms=int(elapsed * 1000),
            data={
                "exit_code": code,
                "stdout": out,
                "stderr": err,
                "timed_out": False,
                "truncated": False,
            },
        ).to_dict()
    env = make_success(
        tool="ssh_exec", host=host,
        data={
            "exit_code": code,
            "stdout": out,
            "stderr": err,
            "timed_out": False,
            "truncated": False,
        },
        text=text,
        request_id=request_id,
        review=_review_summary(review_result),
        duration_ms=int(elapsed * 1000),
    )
    _log.info("ssh_result_envelope", tool=env.tool, status=env.status,
               ok=env.ok, error_code=env.error.code if env.error else None)
    return env.to_dict()


@mcp.tool()
@_tool_boundary("ssh_list_hosts")
def ssh_list_hosts() -> dict:
    """列出 ~/.ssh/config 中配置的主机别名（排除 * 通配项），跨平台适配。"""
    cfg_path = _SSH_DIR / "config"
    if not cfg_path.exists():
        if platform.system() == "Windows":
            system_cfg = pathlib.Path(os.environ.get("PROGRAMDATA", "C:/ProgramData")) / "ssh/ssh_config"
            if system_cfg.exists():
                cfg_path = system_cfg
            else:
                _log.warning("ssh_list_hosts_no_config", path=str(cfg_path))
                return make_failure(
                    ERROR_INVALID_ARGUMENT,
                    "未找到 ~/.ssh/config，请先创建 SSH 配置（可放 Host 别名）。",
                    tool="ssh_list_hosts",
                ).to_dict()
        else:
            _log.warning("ssh_list_hosts_no_config", path=str(cfg_path))
            return make_failure(
                ERROR_INVALID_ARGUMENT,
                "未找到 ~/.ssh/config，请先创建 SSH 配置（可放 Host 别名）。",
                tool="ssh_list_hosts",
            ).to_dict()
    hosts: list[str] = []
    host_configs: dict[str, dict[str, str]] = {}
    current_host: str | None = None
    with cfg_path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.lower().startswith("host "):
                host_names = line.split()[1:]
                for h in host_names:
                    if "*" not in h and "?" not in h:
                        hosts.append(h)
                        host_configs[h] = {}
                        current_host = h
            elif current_host and " " in line:
                key, _, value = line.partition(" ")
                key = key.lower()
                if key in ("hostname", "user", "port", "identityfile"):
                    host_configs[current_host][key] = value.strip()
    _log.info("ssh_list_hosts_done", count=len(hosts))
    if not hosts:
        return make_success(
            tool="ssh_list_hosts", host="",
            data={"hosts": []},
            text="~/.ssh/config 中没有配置 Host 别名。",
        ).to_dict()
    output = ["配置的主机别名："]
    entries: list[dict] = []
    for h in sorted(set(hosts)):
        conf = host_configs.get(h, {})
        info = [h]
        entry = {"alias": h}
        if "hostname" in conf:
            info.append(f"→ {conf.get('user', os.getenv('USERNAME', 'root'))}@{conf['hostname']}:{conf.get('port', '22')}")
            entry["hostname"] = conf["hostname"]
            entry["user"] = conf.get("user", os.getenv("USERNAME", "root"))
            entry["port"] = conf.get("port", "22")
        output.append("  " + " ".join(info))
        entries.append(entry)
    env = make_success(
        tool="ssh_list_hosts", host="",
        data={"hosts": entries},
        text="\n".join(output),
    )
    return env.to_dict()


@mcp.tool()
@_tool_boundary("ssh_upload")
def ssh_upload(host: str, local_path: str, remote_path: str, timeout: int = 60, overwrite: bool = False) -> dict:
    """上传本地文件到远程主机。"""
    local = pathlib.Path(local_path).expanduser().resolve()
    if not local.exists() or not local.is_file():
        return make_failure(
            ERROR_INVALID_ARGUMENT, f"本地文件不存在：{local_path}",
            tool="ssh_upload", host=host,
        ).to_dict()
    size = local.stat().st_size
    if size > _MAX_SINGLE_FILE_BYTES:
        return make_failure(
            ERROR_RESOURCE_LIMIT,
            f"文件大小超过限制（最大{_MAX_SINGLE_FILE_BYTES//1024//1024}MB，当前{round(size/1024/1024, 2)}MB）",
            tool="ssh_upload", host=host,
        ).to_dict()

    ctx = ReviewContext(
        tool="ssh_upload",
        command=f"upload {local_path} -> {remote_path}",
        host=host,
        path=remote_path,
        allow_dangerous=overwrite,
        local_path=str(local),
        remote_path=remote_path,
        overwrite=overwrite,
        mcp_ctx=_get_mcp_ctx(),
    )
    try:
        review_result = _review_context(ctx)
    except ReviewRejectedError as e:
        return make_rejected(str(e), tool="ssh_upload", host=host).to_dict()

    if not overwrite and _SENSITIVE_PATHS.search(remote_path):
        _log.warning("upload_to_sensitive_path", remote_path=remote_path)
        return make_failure(
            ERROR_INVALID_ARGUMENT,
            f"禁止上传到敏感路径：{remote_path}，如需覆盖请设置 overwrite=True",
            tool="ssh_upload", host=host, review=_review_summary(review_result),
        ).to_dict()
    try:
        _reject_remote_traversal(remote_path)
    except ValueError as e:
        return make_failure(
            ERROR_INVALID_ARGUMENT, str(e), tool="ssh_upload", host=host,
            review=_review_summary(review_result),
        ).to_dict()
    client = None
    t0 = time.monotonic()
    try:
        client = _connect(host, timeout=timeout)
        sftp = client.open_sftp()
        info = _sftp_put_atomic(sftp, local, remote_path, overwrite)
        sftp.close()
        elapsed = time.monotonic() - t0
        _log.info("sftp_atomic_write_ok", host=host, remote=remote_path,
                   bytes=info["bytes"], sha256=info["sha256"], elapsed=round(elapsed, 3))
        text = f"上传成功：{local_path} → {host}:{remote_path}（{size} 字节，耗时 {round(elapsed, 2)}s）"
        env = make_success(
            tool="ssh_upload", host=host,
            data={
                "local_path": str(local),
                "remote_path": remote_path,
                "bytes": info["bytes"],
                "sha256": info["sha256"],
            },
            text=text,
            review=_review_summary(review_result),
            duration_ms=int(elapsed * 1000),
        )
        return env.to_dict()
    except (HostKeyError, RuntimeError) as e:
        _log.error("ssh_upload_connect_failed", host=host, remote=remote_path,
                    error=str(e), plan_id=ctx.plan_id)
        return _connect_failure_envelope(
            e, "ssh_upload", host, review=_review_summary(review_result),
        )
    except FileExistsError as e:
        _log.error("ssh_upload_failed", host=host, local_path=str(local),
                    remote_path=remote_path, size=size, error=str(e),
                    plan_id=ctx.plan_id)
        return make_failure(
            ERROR_INVALID_ARGUMENT, str(e), tool="ssh_upload", host=host,
            review=_review_summary(review_result),
        ).to_dict()
    except ChecksumMismatchError as e:
        _log.error("sftp_atomic_write_failed", host=host, remote=remote_path,
                    error=str(e), plan_id=ctx.plan_id)
        return make_failure(
            ERROR_CHECKSUM_MISMATCH, str(e), tool="ssh_upload", host=host,
            review=_review_summary(review_result),
        ).to_dict()
    except OSError as e:
        _log.error("sftp_atomic_write_failed", host=host, remote=remote_path,
                    error=str(e), plan_id=ctx.plan_id)
        return make_failure(
            ERROR_REMOTE_IO_ERROR, str(e), tool="ssh_upload", host=host,
            review=_review_summary(review_result),
        ).to_dict()
    except Exception as e:
        _log.error(
            "ssh_upload_failed",
            host=host,
            local_path=str(local),
            remote_path=remote_path,
            size=size,
            elapsed=round(time.monotonic() - t0, 3),
            plan_id=ctx.plan_id,
            error=str(e),
        )
        return make_failure(
            ERROR_REMOTE_IO_ERROR, str(e), tool="ssh_upload", host=host,
            review=_review_summary(review_result),
        ).to_dict()
    finally:
        if client is not None:
            client.close()


@mcp.tool()
@_tool_boundary("ssh_download")
def ssh_download(host: str, remote_path: str, local_path: str, timeout: int = 60, allow_sensitive: bool = False) -> dict:
    """从远程主机下载文件到本地。"""
    local = pathlib.Path(local_path).expanduser().resolve()
    ctx = ReviewContext(
        tool="ssh_download",
        command=f"download {remote_path} -> {local_path}",
        host=host,
        path=remote_path,
        allow_dangerous=allow_sensitive,
        local_path=str(local),
        remote_path=remote_path,
        mcp_ctx=_get_mcp_ctx(),
    )
    try:
        review_result = _review_context(ctx)
    except ReviewRejectedError as e:
        return make_rejected(str(e), tool="ssh_download", host=host).to_dict()

    if not allow_sensitive and _SENSITIVE_PATHS.search(remote_path):
        _log.warning("download_sensitive_file", remote_path=remote_path)
        return make_failure(
            ERROR_INVALID_ARGUMENT,
            f"禁止下载敏感文件：{remote_path}，确认需要请设置 allow_sensitive=True",
            tool="ssh_download", host=host, review=_review_summary(review_result),
        ).to_dict()
    try:
        _reject_remote_traversal(remote_path)
    except ValueError as e:
        return make_failure(
            ERROR_INVALID_ARGUMENT, str(e), tool="ssh_download", host=host,
            review=_review_summary(review_result),
        ).to_dict()
    local.parent.mkdir(parents=True, exist_ok=True)
    client = None
    t0 = time.monotonic()
    try:
        client = _connect(host, timeout=timeout)
        sftp = client.open_sftp()
        remote_stat = sftp.stat(remote_path)
        if remote_stat.st_size > _MAX_SINGLE_FILE_BYTES:
            sftp.close()
            return make_failure(
                ERROR_RESOURCE_LIMIT,
                f"远程文件大小超过限制（最大{_MAX_SINGLE_FILE_BYTES//1024//1024}MB，"
                f"当前{round(remote_stat.st_size/1024/1024, 2)}MB）",
                tool="ssh_download", host=host, review=_review_summary(review_result),
            ).to_dict()
        info = _sftp_get_atomic(sftp, remote_path, local)
        sftp.close()
        elapsed = time.monotonic() - t0
        _log.info("ssh_download_done", host=host, remote_path=remote_path,
                   local_path=str(local), size=info["bytes"], elapsed=round(elapsed, 3))
        text = f"下载成功：{host}:{remote_path} → {local_path}（{info['bytes']} 字节，耗时 {round(elapsed, 2)}s）"
        env = make_success(
            tool="ssh_download", host=host,
            data={
                "remote_path": remote_path,
                "local_path": str(local),
                "bytes": info["bytes"],
                "sha256": info["sha256"],
            },
            text=text,
            review=_review_summary(review_result),
            duration_ms=int(elapsed * 1000),
        )
        return env.to_dict()
    except (HostKeyError, RuntimeError) as e:
        _log.error("ssh_download_connect_failed", host=host, remote=remote_path,
                    error=str(e), plan_id=ctx.plan_id)
        return _connect_failure_envelope(
            e, "ssh_download", host, review=_review_summary(review_result),
        )
    except ChecksumMismatchError as e:
        _log.error("ssh_download_failed", host=host, remote_path=remote_path,
                    local_path=str(local), error=str(e), plan_id=ctx.plan_id)
        return make_failure(
            ERROR_CHECKSUM_MISMATCH, str(e), tool="ssh_download", host=host,
            review=_review_summary(review_result),
        ).to_dict()
    except FileNotFoundError as e:
        return make_failure(
            ERROR_INVALID_ARGUMENT, str(e), tool="ssh_download", host=host,
            review=_review_summary(review_result),
        ).to_dict()
    except OSError as e:
        _log.error("ssh_download_failed", host=host, remote_path=remote_path,
                    local_path=str(local), error=str(e), plan_id=ctx.plan_id)
        return make_failure(
            ERROR_LOCAL_IO_ERROR, str(e), tool="ssh_download", host=host,
            review=_review_summary(review_result),
        ).to_dict()
    except Exception as e:
        _log.error(
            "ssh_download_failed",
            host=host,
            remote_path=remote_path,
            local_path=str(local),
            elapsed=round(time.monotonic() - t0, 3),
            plan_id=ctx.plan_id,
            error=str(e),
        )
        return make_failure(
            ERROR_REMOTE_IO_ERROR, str(e), tool="ssh_download", host=host,
            review=_review_summary(review_result),
        ).to_dict()
    finally:
        if client is not None:
            client.close()


@mcp.tool()
@_tool_boundary("ssh_exec_batch")
def ssh_exec_batch(host: str, commands: list[str], timeout: int = 30, stop_on_error: bool = True) -> dict:
    """批量执行多条命令，支持错误中断。"""
    if not commands:
        return make_failure(
            ERROR_INVALID_ARGUMENT, "commands 不能为空",
            tool="ssh_exec_batch", host=host,
        ).to_dict()
    batch_payload = "\0".join(commands) + f"\0timeout={timeout}\0stop_on_error={stop_on_error}"
    batch_digest = hashlib.sha256(batch_payload.encode("utf-8")).hexdigest()
    try:
        review_result = _review_context(ReviewContext(
            tool="ssh_exec_batch",
            command=f"batch:{batch_digest}",
            host=host,
            path=f"count={len(commands)}",
            allow_dangerous=False,
            mcp_ctx=_get_mcp_ctx(),
        ))
    except ReviewRejectedError as e:
        return make_rejected(str(e), tool="ssh_exec_batch", host=host).to_dict()

    if timeout <= 0:
        return make_failure(
            ERROR_INVALID_ARGUMENT, "timeout 必须大于 0",
            tool="ssh_exec_batch", host=host,
        ).to_dict()
    deadline = time.monotonic() + timeout
    items: list[dict] = []
    any_failed = False
    stopped_early = False
    for i, cmd in enumerate(commands, 1):
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("批处理超过总 timeout deadline")
            res = ssh_exec(host, cmd, timeout=remaining)
            item: dict = {
                "index": i,
                "command": cmd[:120],
                "status": res.get("status", STATUS_FAILED),
                "ok": res.get("ok", False) and res.get("data", {}).get("exit_code") == 0,
                "exit_code": res.get("data", {}).get("exit_code"),
                "error": res.get("error"),
            }
            items.append(item)
            if item["status"] != STATUS_SUCCEEDED or item["exit_code"] != 0:
                any_failed = True
                if stop_on_error:
                    stopped_early = True
                    break
        except Exception as e:
            any_failed = True
            items.append({
                "index": i,
                "command": cmd[:120],
                "status": STATUS_FAILED,
                "ok": False,
                "exit_code": None,
                "error": {"code": "REMOTE_EXIT_NONZERO", "message": str(e)},
            })
            if stop_on_error:
                stopped_early = True
                break
    status = STATUS_PARTIAL if (any_failed and not stopped_early) else (
        STATUS_SUCCEEDED if not any_failed else STATUS_FAILED
    )
    lines = [f"[batch] executed={len(items)} status={status}"]
    for item in items:
        if item["ok"]:
            lines.append(f"#{item['index']} OK")
        else:
            code = (item.get("error") or {}).get("code", "UNKNOWN")
            lines.append(f"#{item['index']} FAILED {code}")
    data = {
        "items": items,
        "stop_on_error": stop_on_error,
        "stopped_early": stopped_early,
        "executed": len(items),
    }
    text = "\n".join(lines)
    if status == STATUS_SUCCEEDED:
        env = make_success(
            tool="ssh_exec_batch", host=host,
            data=data, text=text,
            review=_review_summary(review_result),
        )
    else:
        code = ERROR_REMOTE_EXIT_NONZERO
        if stopped_early and status == STATUS_FAILED and any(
            (it.get("error") or {}).get("code") == "EXEC_TIMEOUT" for it in items
        ):
            code = ERROR_EXEC_TIMEOUT
        env = make_failure(
            code,
            f"批处理未全部成功：status={status}",
            tool="ssh_exec_batch", host=host, status=status,
            data=data, text=text, review=_review_summary(review_result),
        )
    return env.to_dict()


def _fs_list(host: str, remote_path: str, show_hidden: bool, timeout: int) -> dict:
    """列出远程主机指定目录下的文件和子目录。"""
    if not show_hidden and _SENSITIVE_PATHS.search(remote_path):
        _log.warning("list_sensitive_dir", path=remote_path)
        return make_failure(
            ERROR_INVALID_ARGUMENT, f"禁止列出敏感目录：{remote_path}",
            tool="ssh_filesystem", host=host, data={"action": "list"},
        ).to_dict()
    try:
        _reject_remote_traversal(remote_path)
    except ValueError as e:
        return make_failure(
            ERROR_INVALID_ARGUMENT, str(e), tool="ssh_filesystem", host=host,
            data={"action": "list"},
        ).to_dict()

    ls_cmd = f"ls -la --time-style=long-iso {shlex.quote(remote_path)}"
    if not show_hidden:
        ls_cmd = f"ls -l --time-style=long-iso {shlex.quote(remote_path)}"

    result = ssh_exec(host, ls_cmd, timeout=timeout)
    if result.get("status") != STATUS_SUCCEEDED:
        err = result.get("error") or {}
        return make_failure(
            err.get("code", ERROR_REMOTE_EXIT_NONZERO),
            err.get("message", f"列出目录失败：{remote_path}"),
            tool="ssh_filesystem", host=host, data={"action": "list"},
        ).to_dict()
    out = result.get("data", {}).get("stdout", "")

    lines = out.split("\n")
    output = [f"📂 目录：{remote_path}"]
    output.append("-" * 80)
    output.append(f"{'类型':<3} {'权限':<10} {'大小':<10} {'修改时间':<12} 名称")
    output.append("-" * 80)
    entries: list[dict] = []

    for line in lines:
        line = line.rstrip("\r\n")
        if not line.strip():
            continue
        parts = line.split(maxsplit=6)
        if len(parts) < 7:
            continue
        perm = parts[0]
        size = parts[4]
        tail = parts[6] if len(parts) > 6 else ""
        tail_parts = tail.split(maxsplit=1)
        mtime = f"{parts[5]} {tail_parts[0]}" if tail_parts else parts[5]
        name = tail_parts[1] if len(tail_parts) > 1 else ""
        if name in (".", ".."):
            continue
        if not show_hidden and name.startswith("."):
            continue
        ftype = "📁" if perm.startswith("d") else "📄" if perm.startswith("-") else "🔗" if perm.startswith("l") else "❓"
        try:
            size_num = int(size)
            if size_num < 1024:
                size_str = f"{size_num}B"
            elif size_num < 1024 * 1024:
                size_str = f"{round(size_num/1024, 1)}KB"
            elif size_num < 1024 * 1024 * 1024:
                size_str = f"{round(size_num/1024/1024, 1)}MB"
            else:
                size_str = f"{round(size_num/1024/1024/1024, 2)}GB"
        except Exception:
            size_str = size
        output.append(f"{ftype:<3} {perm:<10} {size_str:<10} {mtime:<12}  {name}")
        entries.append({
            "name": name,
            "type": perm[0],
            "permissions": perm,
            "size": size_str,
            "mtime": mtime,
        })

    env = make_success(
        tool="ssh_filesystem", host=host,
        data={"action": "list", "path": remote_path, "entries": entries},
        text="\n".join(output),
    )
    return env.to_dict()


def _fs_stat(host: str, remote_path: str, timeout: int) -> dict:
    """获取远程文件或目录的详细信息。"""
    result = ssh_exec(host, f"stat {shlex.quote(remote_path)}", timeout=timeout)
    if result.get("status") != STATUS_SUCCEEDED:
        err = result.get("error") or {}
        return make_failure(
            err.get("code", ERROR_REMOTE_EXIT_NONZERO),
            err.get("message", f"stat 失败：{remote_path}"),
            tool="ssh_filesystem", host=host, data={"action": "stat"},
        ).to_dict()
    out = result.get("data", {}).get("stdout", "")
    env = make_success(
        tool="ssh_filesystem", host=host,
        data={"action": "stat", "path": remote_path, "stat": out},
        text=f"📄 {remote_path}\n{out}",
    )
    return env.to_dict()


def _fs_mkdir(host: str, remote_path: str, parents: bool, timeout: int) -> dict:
    """在远程主机创建目录。"""
    if _SENSITIVE_PATHS.search(remote_path):
        _log.warning("mkdir_sensitive_path", path=remote_path)
        return make_failure(
            ERROR_INVALID_ARGUMENT, f"禁止在敏感路径创建目录：{remote_path}",
            tool="ssh_filesystem", host=host, data={"action": "mkdir"},
        ).to_dict()
    try:
        _reject_remote_traversal(remote_path)
    except ValueError as e:
        return make_failure(
            ERROR_INVALID_ARGUMENT, str(e), tool="ssh_filesystem", host=host,
            data={"action": "mkdir"},
        ).to_dict()

    cmd = f"mkdir {'-p' if parents else ''} {shlex.quote(remote_path)}"
    try:
        review_result = _review_context(ReviewContext(
            tool="ssh_filesystem",
            command=cmd,
            host=host,
            path=remote_path,
            remote_path=remote_path,
            recursive=parents,
            allow_dangerous=True,
            mcp_ctx=_get_mcp_ctx(),
        ))
    except ReviewRejectedError as e:
        return make_rejected(str(e), tool="ssh_filesystem", host=host).to_dict()
    result = ssh_exec(host, cmd, timeout=timeout, allow_dangerous=True)
    if result.get("status") == STATUS_SUCCEEDED:
        return make_success(
            tool="ssh_filesystem", host=host,
            data={"action": "mkdir", "path": remote_path, "parents": parents},
            text=f"✅ 目录创建成功：{remote_path}",
            review=_review_summary(review_result),
        ).to_dict()
    err = result.get("error") or {}
    return make_failure(
        err.get("code", ERROR_REMOTE_EXIT_NONZERO),
        err.get("message", f"目录创建失败：{remote_path}"),
        tool="ssh_filesystem", host=host, review=_review_summary(review_result),
        data={"action": "mkdir"},
    ).to_dict()


def _fs_remove(host: str, remote_path: str, recursive: bool, timeout: int) -> dict:
    """删除远程主机上的文件或目录。"""
    ctx = ReviewContext(
        tool="ssh_filesystem",
        command=f"remove {remote_path} (recursive={recursive})",
        host=host,
        path=remote_path,
        allow_dangerous=recursive,
        remote_path=remote_path,
        recursive=recursive,
        mcp_ctx=_get_mcp_ctx(),
    )
    try:
        review_result = _review_context(ctx)
    except ReviewRejectedError as e:
        return make_rejected(str(e), tool="ssh_filesystem", host=host).to_dict()

    if _SENSITIVE_PATHS.search(remote_path):
        _log.warning("remove_sensitive_path", path=remote_path)
        return make_failure(
            ERROR_INVALID_ARGUMENT, f"禁止删除敏感路径：{remote_path}",
            tool="ssh_filesystem", host=host, review=_review_summary(review_result),
            data={"action": "remove"},
        ).to_dict()
    try:
        _reject_remote_traversal(remote_path)
    except ValueError as e:
        return make_failure(
            ERROR_INVALID_ARGUMENT, str(e), tool="ssh_filesystem", host=host,
            review=_review_summary(review_result), data={"action": "remove"},
        ).to_dict()

    if not recursive:
        cmd = f"rm -f {shlex.quote(remote_path)}"
    else:
        cmd = f"rm -rf {shlex.quote(remote_path)}"

    result = ssh_exec(host, cmd, timeout=timeout, allow_dangerous=True)
    if result.get("status") == STATUS_SUCCEEDED:
        return make_success(
            tool="ssh_filesystem", host=host,
            data={"action": "remove", "path": remote_path, "recursive": recursive},
            text=f"✅ 删除成功：{remote_path}",
            review=_review_summary(review_result),
        ).to_dict()
    err = result.get("error") or {}
    return make_failure(
        err.get("code", ERROR_REMOTE_EXIT_NONZERO),
        err.get("message", f"删除失败：{remote_path}"),
        tool="ssh_filesystem", host=host, review=_review_summary(review_result),
        data={"action": "remove"},
    ).to_dict()


@mcp.tool()
@_tool_boundary("ssh_filesystem")
def ssh_filesystem(
    host: str,
    action: Literal["list", "stat", "mkdir", "remove"],
    remote_path: str,
    parents: bool = True,
    recursive: bool = False,
    show_hidden: bool = False,
    timeout: int = 10,
) -> dict:
    """远程文件系统操作：list（列出目录）/ stat（状态）/ mkdir（创建目录）/ remove（删除）。

    `action` 决定操作类型：
    - `list`：列出 `remote_path` 下的文件和子目录（`show_hidden` 控制是否显示隐藏文件）
    - `stat`：获取 `remote_path` 的详细信息
    - `mkdir`：创建目录（`parents=True` 时 `mkdir -p`）
    - `remove`：删除文件或目录（`recursive=True` 时递归删除）
    """
    if not remote_path.strip():
        return make_failure(
            ERROR_INVALID_ARGUMENT, "remote_path 不能为空",
            tool="ssh_filesystem", host=host,
        ).to_dict()
    if action == "list":
        return _fs_list(host, remote_path, show_hidden, timeout)
    if action == "stat":
        return _fs_stat(host, remote_path, timeout)
    if action == "mkdir":
        return _fs_mkdir(host, remote_path, parents, timeout)
    if action == "remove":
        return _fs_remove(host, remote_path, recursive, timeout)
    return make_failure(
        ERROR_INVALID_ARGUMENT, f"不支持的 action：{action}",
        tool="ssh_filesystem", host=host,
    ).to_dict()


@mcp.tool()
@_tool_boundary("ssh_upload_dir")
def ssh_upload_dir(host: str, local_dir: str, remote_dir: str, overwrite: bool = False, timeout: int = 300) -> dict:
    """上传本地目录到远程主机（递归上传所有文件）。"""
    local = pathlib.Path(local_dir).expanduser().resolve()
    if not local.exists() or not local.is_dir():
        return make_failure(
            ERROR_INVALID_ARGUMENT, f"本地目录不存在：{local_dir}",
            tool="ssh_upload_dir", host=host,
        ).to_dict()

    if not overwrite and _SENSITIVE_PATHS.search(remote_dir):
        _log.warning("upload_dir_to_sensitive_path", path=remote_dir)
        return make_failure(
            ERROR_INVALID_ARGUMENT,
            f"禁止上传到敏感路径：{remote_dir}，如需覆盖请设置 overwrite=True",
            tool="ssh_upload_dir", host=host,
        ).to_dict()
    try:
        _reject_remote_traversal(remote_dir)
    except ValueError as e:
        return make_failure(
            ERROR_INVALID_ARGUMENT, str(e), tool="ssh_upload_dir", host=host,
        ).to_dict()

    plan_ctx = ReviewContext(
        tool="ssh_upload_dir",
        command=f"upload_dir {local_dir} -> {remote_dir}",
        host=host,
        path=remote_dir,
        local_path=str(local),
        remote_path=remote_dir,
        recursive=True,
        overwrite=overwrite,
        mcp_ctx=_get_mcp_ctx(),
    )
    try:
        review_result = _review_context(plan_ctx)
    except ReviewRejectedError as e:
        return make_rejected(str(e), tool="ssh_upload_dir", host=host).to_dict()

    try:
        local_entries = _bounded_walk(local)
    except ResourceLimitError as e:
        return make_failure(
            ERROR_RESOURCE_LIMIT, str(e), tool="ssh_upload_dir", host=host,
            review=_review_summary(review_result),
        ).to_dict()

    client = None
    t0 = time.monotonic()
    uploaded = 0
    total_size = 0
    skipped: list[dict] = []
    failed: list[dict] = []

    try:
        client = _connect(host, timeout=timeout)
        sftp = client.open_sftp()
        try:
            sftp.stat(remote_dir)
        except FileNotFoundError:
            sftp.mkdir(remote_dir)

        for entry in local_entries:
            rel = entry["path"].relative_to(local)
            remote_path = f"{remote_dir}/{rel.as_posix()}"
            if entry["is_dir"]:
                try:
                    sftp.stat(remote_path)
                except FileNotFoundError:
                    sftp.mkdir(remote_path)
                continue
            if entry["size"] > _MAX_SINGLE_FILE_BYTES:
                skipped.append({"path": str(rel), "reason": "size_limit"})
                continue
            try:
                info = _sftp_put_atomic(sftp, entry["path"], remote_path, overwrite)
                uploaded += 1
                total_size += info["bytes"]
            except FileExistsError:
                skipped.append({"path": str(rel), "reason": "exists"})
            except ChecksumMismatchError as e:
                failed.append({"path": str(rel), "reason": str(e)})
                _log.error("sftp_atomic_write_failed", host=host, remote=remote_path,
                            error=str(e), plan_id=plan_ctx.plan_id)
                break
            except OSError as e:
                failed.append({"path": str(rel), "reason": str(e)})
                _log.error("sftp_atomic_write_failed", host=host, remote=remote_path,
                            error=str(e), plan_id=plan_ctx.plan_id)
                break

        sftp.close()
        elapsed = time.monotonic() - t0
        status = STATUS_PARTIAL if (failed or skipped) else STATUS_SUCCEEDED
        _log.info("ssh_upload_dir_done", host=host, local_dir=str(local),
                   remote_dir=remote_dir, files=uploaded, size=total_size,
                   skipped=len(skipped), failed=len(failed), elapsed=round(elapsed, 3))
        text = (f"✅ 目录上传完成：{local_dir} → {host}:{remote_dir}（status={status}）\n"
                f"📊 上传文件：{uploaded} 个，总大小：{round(total_size/1024/1024, 2)}MB，"
                f"耗时：{round(elapsed, 2)}s"
                + (f"，跳过 {len(skipped)} 个，失败 {len(failed)} 个" if status == STATUS_PARTIAL else ""))
        env = make_success(
            tool="ssh_upload_dir", host=host,
            data={
                "local_dir": str(local),
                "remote_dir": remote_dir,
                "uploaded": uploaded,
                "bytes": total_size,
                "skipped": skipped,
                "failed": failed,
            },
            text=text,
            review=_review_summary(review_result),
            duration_ms=int(elapsed * 1000),
            status=status,
        )
        return env.to_dict()
    except (HostKeyError, RuntimeError) as e:
        _log.error("ssh_upload_dir_connect_failed", host=host, remote=remote_dir,
                    error=str(e), plan_id=plan_ctx.plan_id)
        return _connect_failure_envelope(
            e, "ssh_upload_dir", host, review=_review_summary(review_result),
        )
    except ResourceLimitError as e:
        _log.error("sftp_bounded_walk_limit", host=host, remote=remote_dir, error=str(e))
        return make_failure(
            ERROR_RESOURCE_LIMIT, str(e), tool="ssh_upload_dir", host=host,
            review=_review_summary(review_result),
        ).to_dict()
    except Exception as e:
        _log.error(
            "ssh_upload_dir_failed",
            host=host,
            local_dir=str(local),
            remote_dir=remote_dir,
            files=uploaded,
            size=total_size,
            elapsed=round(time.monotonic() - t0, 3),
            error=str(e),
            plan_id=plan_ctx.plan_id,
        )
        return make_failure(
            ERROR_REMOTE_IO_ERROR, str(e), tool="ssh_upload_dir", host=host,
            review=_review_summary(review_result),
        ).to_dict()
    finally:
        if client is not None:
            client.close()


@mcp.tool()
@_tool_boundary("ssh_download_dir")
def ssh_download_dir(host: str, remote_dir: str, local_dir: str, allow_sensitive: bool = False, timeout: int = 300) -> dict:
    """从远程主机下载目录到本地（递归下载所有文件）。"""
    if not allow_sensitive and _SENSITIVE_PATHS.search(remote_dir):
        _log.warning("download_sensitive_dir", path=remote_dir)
        return make_failure(
            ERROR_INVALID_ARGUMENT,
            f"禁止下载敏感目录：{remote_dir}，确认需要请设置 allow_sensitive=True",
            tool="ssh_download_dir", host=host,
        ).to_dict()
    try:
        _reject_remote_traversal(remote_dir)
    except ValueError as e:
        return make_failure(
            ERROR_INVALID_ARGUMENT, str(e), tool="ssh_download_dir", host=host,
        ).to_dict()

    local = pathlib.Path(local_dir).expanduser().resolve()
    plan_ctx = ReviewContext(
        tool="ssh_download_dir",
        command=f"download_dir {remote_dir} -> {local_dir}",
        host=host,
        path=remote_dir,
        local_path=str(local),
        remote_path=remote_dir,
        recursive=True,
        mcp_ctx=_get_mcp_ctx(),
    )
    try:
        review_result = _review_context(plan_ctx)
    except ReviewRejectedError as e:
        return make_rejected(str(e), tool="ssh_download_dir", host=host).to_dict()
    local.mkdir(parents=True, exist_ok=True)

    client = None
    t0 = time.monotonic()
    downloaded = 0
    total_size = 0
    skipped: list[dict] = []
    failed: list[dict] = []

    try:
        client = _connect(host, timeout=timeout)
        sftp = client.open_sftp()
        try:
            remote_entries = _bounded_walk(remote_dir, sftp=sftp)
        except ResourceLimitError as e:
            sftp.close()
            _log.error("sftp_bounded_walk_limit", host=host, remote=remote_dir, error=str(e))
            return make_failure(
                ERROR_RESOURCE_LIMIT, str(e), tool="ssh_download_dir", host=host,
                review=_review_summary(review_result),
            ).to_dict()

        for entry in remote_entries:
            remote_item = entry["path"]
            rel = pathlib.PurePosixPath(remote_item).relative_to(remote_dir)
            local_item = local / rel
            if entry["is_dir"]:
                local_item.mkdir(parents=True, exist_ok=True)
                continue
            if entry["size"] > _MAX_SINGLE_FILE_BYTES:
                skipped.append({"path": str(rel), "reason": "size_limit"})
                continue
            local_item.parent.mkdir(parents=True, exist_ok=True)
            try:
                info = _sftp_get_atomic(sftp, remote_item, local_item)
                downloaded += 1
                total_size += info["bytes"]
            except ChecksumMismatchError as e:
                failed.append({"path": str(rel), "reason": str(e)})
                _log.error("sftp_atomic_write_failed", host=host, remote=remote_item,
                            error=str(e), plan_id=plan_ctx.plan_id)
                break
            except OSError as e:
                failed.append({"path": str(rel), "reason": str(e)})
                _log.error("sftp_atomic_write_failed", host=host, remote=remote_item,
                            error=str(e), plan_id=plan_ctx.plan_id)
                break

        sftp.close()
        elapsed = time.monotonic() - t0
        status = STATUS_PARTIAL if (failed or skipped) else STATUS_SUCCEEDED
        _log.info("ssh_download_dir_done", host=host, remote_dir=remote_dir,
                   local_dir=str(local), files=downloaded, size=total_size,
                   skipped=len(skipped), failed=len(failed), elapsed=round(elapsed, 3))
        text = (f"✅ 目录下载完成：{host}:{remote_dir} → {local_dir}（status={status}）\n"
                f"📊 下载文件：{downloaded} 个，总大小：{round(total_size/1024/1024, 2)}MB，"
                f"耗时：{round(elapsed, 2)}s"
                + (f"，跳过 {len(skipped)} 个，失败 {len(failed)} 个" if status == STATUS_PARTIAL else ""))
        env = make_success(
            tool="ssh_download_dir", host=host,
            data={
                "remote_dir": remote_dir,
                "local_dir": str(local),
                "downloaded": downloaded,
                "bytes": total_size,
                "skipped": skipped,
                "failed": failed,
            },
            text=text,
            review=_review_summary(review_result),
            duration_ms=int(elapsed * 1000),
            status=status,
        )
        return env.to_dict()
    except (HostKeyError, RuntimeError) as e:
        _log.error("ssh_download_dir_connect_failed", host=host, remote=remote_dir,
                    error=str(e), plan_id=plan_ctx.plan_id)
        return _connect_failure_envelope(
            e, "ssh_download_dir", host, review=_review_summary(review_result),
        )
    except Exception as e:
        _log.error(
            "ssh_download_dir_failed",
            host=host,
            remote_dir=remote_dir,
            local_dir=str(local),
            files=downloaded,
            size=total_size,
            elapsed=round(time.monotonic() - t0, 3),
            error=str(e),
            plan_id=plan_ctx.plan_id,
        )
        return make_failure(
            ERROR_REMOTE_IO_ERROR, str(e), tool="ssh_download_dir", host=host,
            review=_review_summary(review_result),
        ).to_dict()
    finally:
        if client is not None:
            client.close()


# ---------------------------------------------------------------------------
# 审核模式管理工具
# ---------------------------------------------------------------------------


@mcp.tool()
@_tool_boundary("ssh_get_review_mode")
def ssh_get_review_mode() -> dict:
    """获取当前审核模式及状态信息。"""
    status = _review_engine.get_status()
    lines = [
        f"🔒 审核模式: {status['mode']}",
        f"📋 白名单文件: {status['whitelist_file']}",
        f"   文件存在: {'是' if status['whitelist_exists'] else '否（使用内置默认规则）'}",
        f"⏱️  人工确认超时: {status['manual_timeout']}s",
        "",
        "可选模式:",
        "  off       - 关闭审核，所有操作直接放行（仅记日志）",
        "  whitelist - 白名单审核，仅允许匹配规则的命令（默认）",
        "  manual    - 人工审核，每条命令需人工确认",
        "  smart     - 智能审核，本地规则初筛，不确定时转人工",
    ]
    env = make_success(
        tool="ssh_get_review_mode",
        host="",
        data={"status": status},
        text="\n".join(lines),
    )
    return env.to_dict()


@mcp.tool()
@_tool_boundary("ssh_set_review_mode")
def ssh_set_review_mode(
    mode: Literal["off", "whitelist", "manual", "smart"],
) -> dict:
    """动态切换审核模式。可选: off / whitelist / manual / smart。"""
    old_mode = _review_engine.get_mode()
    success, message = _review_engine.set_mode(mode)
    data = {"old_mode": old_mode, "new_mode": mode, "success": success}
    text = f"✅ {message}" if success else f"❌ {message}"
    if success:
        return make_success(
            tool="ssh_set_review_mode",
            host="",
            data=data,
            text=text,
        ).to_dict()
    return make_failure(
        ERROR_INVALID_ARGUMENT, message,
        tool="ssh_set_review_mode",
        data=data,
        text=text,
    ).to_dict()


@mcp.tool()
@_tool_boundary("ssh_get_audit_logs")
def ssh_get_audit_logs(
    limit: int = 50,
    host: str | None = None,
    tool: str | None = None,
    since_minutes: int = 0,
) -> dict:
    """查询最近的行为日志（只读，供 AI 分析）。

    读取 ~/.ssh/mcp-ssh.log（或 SSH_LOG_FILE），按事件聚合为统一行为视图，
    返回每条含 timestamp/host/username/tool/args/status/duration_ms。
    支持按 host / tool / since_minutes 过滤；输出受 limit 与大小上限约束。
    """
    limit = max(1, min(int(limit), 500))
    since_minutes = max(0, int(since_minutes))
    log_path = pathlib.Path(os.getenv("SSH_LOG_FILE", "")) if os.getenv("SSH_LOG_FILE") else None
    if log_path is None:
        log_path = _SSH_DIR / "mcp-ssh.log"

    if not log_path.exists():
        _log.error("ssh_log_query_failed", path=str(log_path), reason="file_missing")
        return make_failure(
            ERROR_LOCAL_IO_ERROR,
            f"日志文件不存在: {log_path}",
            tool="ssh_get_audit_logs",
        ).to_dict()

    username_map: dict[str, str] = {}
    behavior: list[dict] = []
    envelope_status: dict[tuple[str, str], str] = {}
    skipped = 0

    try:
        with log_path.open("r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError as e:
        _log.error("ssh_log_query_failed", path=str(log_path), reason="read_failed", error=str(e))
        return make_failure(
            ERROR_LOCAL_IO_ERROR,
            f"日志文件读取失败: {e}",
            tool="ssh_get_audit_logs",
        ).to_dict()

    # 第一遍：建立 username 映射 + envelope status（按 tool+ts 关联）
    for line in lines:
        try:
            entry = json.loads(line)
        except (ValueError, TypeError):
            skipped += 1
            continue
        event = entry.get("event", "")
        if event == "ssh_connected" and entry.get("host"):
            username_map[entry["host"]] = entry.get("username") or ""
        elif event == "ssh_result_envelope" and entry.get("tool"):
            envelope_status[(entry["tool"], entry.get("ts", ""))] = entry.get("status") or "unknown"

    cutoff_ts = None
    if since_minutes > 0:
        cutoff_ts = time.time() - since_minutes * 60

    # 第二遍：聚合行为视图
    for line in lines:
        try:
            entry = json.loads(line)
        except (ValueError, TypeError):
            continue
        event = entry.get("event", "")
        ts_raw = entry.get("ts", "")
        try:
            ts_str = ts_raw.replace("Z", "+00:00")
            ts = datetime.fromisoformat(ts_str)
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            ts_epoch = ts.timestamp()
        except (ValueError, TypeError, OSError):
            ts_epoch = None
        if cutoff_ts is not None and (ts_epoch is None or ts_epoch < cutoff_ts):
            continue

        record: dict | None = None
        if event in ("ssh_exec_done", "ssh_exec_batch_done", "sftp_atomic_write_ok",
                     "sftp_atomic_write_failed", "sftp_bounded_walk_limit"):
            tool_name = "ssh_exec" if event == "ssh_exec_done" else (
                "ssh_exec_batch" if event == "ssh_exec_batch_done" else event
            )
            args: dict = {}
            if "command" in entry:
                args["command"] = entry["command"]
            if "remote" in entry:
                args["remote_path"] = entry["remote"]
            if "commands_count" in entry:
                args["commands_count"] = entry["commands_count"]
            record = {
                "timestamp": ts_raw,
                "host": entry.get("host") or "",
                "username": username_map.get(entry.get("host") or "", None),
                "tool": tool_name,
                "args": args,
                "status": envelope_status.get((tool_name, ts_raw), "unknown"),
                "duration_ms": round((entry.get("elapsed") or 0) * 1000),
            }
        elif event == "review_mode_changed":
            record = {
                "timestamp": ts_raw,
                "host": "",
                "username": None,
                "tool": "ssh_set_review_mode",
                "args": {"old": entry.get("old"), "new": entry.get("new")},
                "status": "succeeded",
                "duration_ms": 0,
            }
        if record is None:
            continue
        if host and record["host"] != host:
            continue
        if tool and record["tool"] != tool:
            continue
        behavior.append(record)

    # 时间倒序（最新在前）
    behavior.sort(key=lambda r: r["timestamp"], reverse=True)
    # 单条 args 脱敏 + 截断
    for record in behavior:
        record["args"] = _redact_log_args(record["args"])
        record["args"] = _truncate_log_args(record["args"])
    # limit 截断 + 总输出控制
    total = len(behavior)
    truncated = total > limit
    behavior = behavior[:limit]
    output_bytes = sum(
        len(json.dumps(r, ensure_ascii=False, default=str)) for r in behavior
    )
    max_output = 200 * 1024
    while behavior and output_bytes > max_output and len(behavior) > 1:
        behavior = behavior[:-1]
        output_bytes = sum(
            len(json.dumps(r, ensure_ascii=False, default=str)) for r in behavior
        )

    _log.info("ssh_get_audit_logs_done", count=len(behavior), total=total,
              filtered_host=host, filtered_tool=tool, skipped=skipped)
    return make_success(
        tool="ssh_get_audit_logs",
        host="",
        data={
            "logs": behavior,
            "total": total,
            "returned": len(behavior),
            "skipped": skipped,
            "truncated": truncated,
        },
        text=_render_log_query_text(behavior, total),
    ).to_dict()


def _redact_log_args(args: dict) -> dict:
    """脱敏 args 中 export K=V 的值，避免凭据泄露。"""
    redacted: dict = {}
    for key, value in args.items():
        if isinstance(value, str):
            redacted[key] = re.sub(
                r"(export\s+[A-Za-z_][A-Za-z0-9_]*=)[^;]+", r"\1***", value
            )
        else:
            redacted[key] = value
    return redacted


def _truncate_log_args(args: dict) -> dict:
    """单条 args 序列化超过 500 字符时截断并标记 truncated。"""
    text = json.dumps(args, ensure_ascii=False, default=str)
    if len(text) <= 500:
        return args
    return {"_truncated": True, "summary": text[:500]}


def _render_log_query_text(records: list[dict], total: int) -> str:
    """渲染人类可读的日志查询结果文本。"""
    if not records:
        return f"未找到匹配日志（总数 {total} 条）。"
    lines = [f"最近 {len(records)} 条行为日志（共 {total} 条）:"]
    for r in records:
        host = r.get("host") or "-"
        user = r.get("username") or "-"
        ts = r.get("timestamp") or "-"
        tool = r.get("tool") or "-"
        status = r.get("status") or "unknown"
        args = json.dumps(r.get("args") or {}, ensure_ascii=False)[:120]
        lines.append(f"[{ts}] {user}@{host} {tool} → {status} args={args}")
    return "\n".join(lines)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
