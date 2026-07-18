"""SSH control MCP server.

复用本地 ~/.ssh/config 的主机别名与凭据；密钥优先，密码兜底。
密码通过环境变量 SSH_PASS_<HOST> 提供（点/横线转下划线，全大写），
或 SSH_PASS 作为全局兜底。密钥不会落配置文件。

跨平台支持：Windows/Linux/macOS，自动适配编码、路径、shell 差异。
安全防护：命令注入检测、危险命令拦截、输出编码自动识别。
"""
from __future__ import annotations

import os
import pathlib
import platform
import re
import shlex
import socket
import time
from typing import Optional

import paramiko
from charset_normalizer import from_bytes
from mcp.server.fastmcp import FastMCP
from paramiko import SSHConfig

from logger import get_logger

mcp = FastMCP("ssh")
_log = get_logger()

# 跨平台 SSH 目录适配
if platform.system() == "Windows":
    _SSH_DIR = pathlib.Path(os.environ.get("USERPROFILE", pathlib.Path.home())) / ".ssh"
else:
    _SSH_DIR = pathlib.Path.home() / ".ssh"
_DEFAULT_KEY_NAMES = ("id_ed25519", "id_ecdsa", "id_rsa", "id_dsa")

# 危险命令拦截列表（防止误操作）
_DANGEROUS_COMMANDS = re.compile(
    r"^\s*(rm\s+(-rf?|--recursive)\s+/(?!tmp|var/tmp)|mkfs|dd\s+if=|format\s+[a-z]:|shutdown|reboot|halt|poweroff|:(){ :|:& };:|fork\s*bomb)",
    re.IGNORECASE
)
# 命令注入特征检测（排除合法的 && || 管道操作，只检测恶意特征）
_INJECTION_PATTERNS = re.compile(
    r";\s*(rm|wget|curl|nc|ncat|bash|sh|chmod|chown|passwd|useradd)|`[^`]+`|\$\([^)]+\)|>\s*/dev/(tcp|udp)|<\s*\(|wget\s+https?://.*\|\s*(sh|bash)|curl\s+https?://.*\|\s*(sh|bash)|nc\s+.*-e|ncat\s+.*-e|\|\s*(sh|bash|zsh|python|perl)\s*$",
    re.IGNORECASE
)
# 敏感文件路径保护
_SENSITIVE_PATHS = re.compile(
    r"/etc/(passwd|shadow|ssh/sshd_config|sudoers)|/root/\.ssh/|~/.ssh/id_",
    re.IGNORECASE
)


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
        # Windows 下 socket 连接错误码映射
        sock.connect((hostname, port))
        _log.debug("tcp_probe_ok", host=host, hostname=hostname, port=port)
    except socket.timeout:
        _log.warning("tcp_probe_timeout", host=host, hostname=hostname, port=port, timeout=timeout)
        raise RuntimeError(
            f"主机不可达：{hostname}:{port} 连接超时（{timeout}s），"
            f"请检查 IP/端口是否正确、主机是否在线、防火墙是否放行。"
        )
    except OSError as e:
        err_msg = str(e)
        # 跨平台错误码适配
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
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # 1) 密钥：config 里的 IdentityFile + 默认密钥 + ssh-agent
    identity_files: list[str] = []
    ident = conf.get("identityfile")
    if ident:
        identity_files.extend(ident if isinstance(ident, list) else [ident])
    for name in _DEFAULT_KEY_NAMES:
        p = _SSH_DIR / name
        if p.exists() and str(p) not in identity_files:
            identity_files.append(str(p))

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
        except paramiko.SSHException as e:
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
        except paramiko.AuthenticationException:
            _log.warning("auth_failed", host=host, hostname=hostname, port=port,
                          username=username, reason="bad_password")
            raise RuntimeError(
                f"认证失败：{username}@{hostname}:{port} — 密码错误。"
                f"请检查环境变量 SSH_PASS_{host.upper().replace('.', '_').replace('-', '_')}。"
            )
        except paramiko.SSHException as e:
            _log.debug("password_auth_error", host=host, error=str(e))
            last_err = e

    _log.error("connect_failed", host=host, hostname=hostname, port=port,
                username=username, last_error=str(last_err))
    raise RuntimeError(
        f"无法连接 {host}（{username}@{hostname}:{port}）："
        f"无可用密钥/密码。最后错误：{last_err}"
    )


def _decode_output(raw: bytes) -> str:
    """自动检测输出编码，解决跨平台/跨语言编码错乱问题。
    优先尝试 UTF-8，然后尝试中文编码，最后用 charset-normalizer 自动识别。
    """
    if not raw:
        return ""
    # 优先尝试 UTF-8
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        pass
    # 优先尝试常用中文编码（避免 charset-normalizer 误判）
    for enc in ("gbk", "cp936", "gb2312", "big5"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    # 自动检测编码
    try:
        result = from_bytes(raw).best()
        if result:
            return str(result)
    except Exception:
        pass
    # 最终兜底
    for enc in ("latin-1",):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    # 最终兜底：替换错误字符
    return raw.decode("utf-8", errors="replace")


def _read_channel(channel: paramiko.Channel, timeout: float) -> str:
    """分块读取 channel 输出，使用 channel 级超时避免 PipeTimeout。
    跨平台优化：适配不同系统的输出缓冲行为。
    """
    channel.settimeout(timeout)
    chunks: list[bytes] = []
    deadline = time.monotonic() + timeout
    # Windows 系统下增加初始等待时间，避免输出不完整
    if platform.system() == "Windows":
        time.sleep(0.05)
    while not channel.exit_status_ready():
        if channel.recv_ready():
            chunks.append(channel.recv(65536))
        else:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(0.05)
    # 收尾：读取剩余数据，最多等待 2 秒确保输出完整
    end_wait = time.monotonic() + 2.0
    while time.monotonic() < end_wait:
        if channel.recv_ready():
            chunks.append(channel.recv(65536))
            end_wait = time.monotonic() + 0.2  # 有新数据就延长等待
        else:
            if channel.exit_status_ready():
                break
            time.sleep(0.05)
    return _decode_output(b"".join(chunks))


def _validate_command(command: str, allow_dangerous: bool = False) -> None:
    """命令安全校验：检测注入特征、危险命令、敏感文件访问，防止命令混淆/误操作/数据泄露。"""
    if not command.strip():
        raise ValueError("命令不能为空")
    
    # 命令长度限制，防止超长命令攻击
    if len(command) > 10000:
        _log.warning("command_too_long", length=len(command))
        raise RuntimeError("命令长度超过限制（最大10000字符）")
    
    # 检测敏感文件访问（防止密钥/密码泄露）
    if not allow_dangerous and _SENSITIVE_PATHS.search(command):
        _log.warning("sensitive_path_access_detected", command=command[:200])
        raise RuntimeError(
            "检测到敏感文件访问（/etc/passwd、/etc/shadow、SSH密钥等），已拦截执行。"
            "确认要访问请设置 allow_dangerous=True 参数。"
        )
    
    # 检测命令注入特征
    if _INJECTION_PATTERNS.search(command):
        _log.warning("command_injection_detected", command=command[:200])
        raise RuntimeError(
            "检测到潜在命令注入特征（反弹shell、远程脚本执行、未授权命令拼接等），已拦截执行。"
            "如需执行包含特殊字符的命令，请显式说明用途并设置 allow_dangerous=True。"
        )
    
    # 检测高危系统命令
    if not allow_dangerous and _DANGEROUS_COMMANDS.search(command):
        _log.warning("dangerous_command_detected", command=command[:200])
        raise RuntimeError(
            f"检测到高危命令（可能导致系统损坏/数据丢失/服务中断）：{command[:50]}...，"
            "确认要执行请设置 allow_dangerous=True 参数。"
        )
    
    # 审计日志：记录所有执行的命令
    _log.debug("command_validated", command=command[:500], allow_dangerous=allow_dangerous)


def _normalize_command(command: str, shell: Optional[str] = None) -> str:
    """跨平台命令标准化：自动适配不同系统的 shell 和换行符。
    注意：默认不添加本地shell前缀，远程服务器默认使用用户默认shell（通常是bash/sh）。
    """
    # 统一换行符为 LF
    command = command.replace("\r\n", "\n").replace("\r", "\n")
    # 只有显式指定shell或者明确是Windows命令时才添加前缀
    if shell is not None:
        if shell.lower() in ("cmd", "cmd.exe"):
            command = f"cmd /c {command}"
        elif shell.lower() in ("powershell", "pwsh", "ps"):
            command = f"powershell -NoProfile -Command \"{command.replace('`', '``').replace('"', '`"')}\""
        elif shell.lower() in ("bash", "sh", "zsh"):
            command = f"{shell} -c {shlex.quote(command)}"
    else:
        # 仅当明确检测到Windows命令时才添加cmd前缀，避免误判远程Linux命令
        if all(cmd in command.lower() for cmd in ("dir ", "\\")) or any(cmd in command.lower() for cmd in ("ipconfig", "netstat -an", "tasklist")):
            command = f"cmd /c {command}"
    return command


@mcp.tool()
def ssh_exec(
    host: str,
    command: str,
    timeout: int = 30,
    shell: Optional[str] = None,
    allow_dangerous: bool = False,
    environment: Optional[dict[str, str]] = None
) -> str:
    """在远程主机上执行一条 shell 命令并返回结果。

    Args:
        host: ~/.ssh/config 中的主机别名，或 user@hostname 形式。
        command: 要执行的 shell 命令，自动处理跨平台编码和特殊字符转义。
        timeout: 命令超时秒数，默认 30。
        shell: 指定执行 shell（如 "bash", "sh", "cmd", "powershell"），默认自动检测。
        allow_dangerous: 是否允许执行高危命令（rm -rf /、mkfs、shutdown 等），默认 False。
        environment: 额外的环境变量字典，会在命令执行前设置。

    Returns:
        包含 exit_code / stdout / stderr 的文本，自动适配编码避免乱码。
    """
    # 安全校验
    _validate_command(command, allow_dangerous=allow_dangerous)
    # 命令标准化和跨平台适配
    command = _normalize_command(command, shell=shell)
    # 处理环境变量
    if environment:
        env_prefix = " ".join(f"export {k}={shlex.quote(v)};" for k, v in environment.items())
        command = f"{env_prefix} {command}"

    client = _connect(host, timeout=timeout)
    t0 = time.monotonic()
    try:
        _stdin, stdout, stderr = client.exec_command(
            command,
            timeout=timeout,
            get_pty=True  # 分配伪终端，解决部分命令输出不完整/挂起问题
        )
        out = _read_channel(stdout.channel, timeout)
        err = _read_channel(stderr.channel, timeout)
        code = stdout.channel.recv_exit_status()
    finally:
        client.close()

    elapsed = time.monotonic() - t0
    _log.info("ssh_exec_done", host=host, command=command[:120],
               exit_code=code, elapsed=round(elapsed, 3),
               out_len=len(out), err_len=len(err), shell=shell)

    parts = [f"[exit_code] {code}"]
    if out:
        parts.append(f"[stdout]\n{out.rstrip()}")
    if err:
        parts.append(f"[stderr]\n{err.rstrip()}")
    return "\n".join(parts)


@mcp.tool()
def ssh_list_hosts() -> str:
    """列出 ~/.ssh/config 中配置的主机别名（排除 * 通配项），跨平台适配。"""
    cfg_path = _SSH_DIR / "config"
    if not cfg_path.exists():
        # Windows 下检查 ProgramData 下的系统级 SSH 配置
        if platform.system() == "Windows":
            system_cfg = pathlib.Path(os.environ.get("PROGRAMDATA", "C:/ProgramData")) / "ssh/ssh_config"
            if system_cfg.exists():
                cfg_path = system_cfg
            else:
                _log.warning("ssh_list_hosts_no_config", path=str(cfg_path))
                return "未找到 ~/.ssh/config，请先创建 SSH 配置（可放 Host 别名）。"
        else:
            _log.warning("ssh_list_hosts_no_config", path=str(cfg_path))
            return "未找到 ~/.ssh/config，请先创建 SSH 配置（可放 Host 别名）。"
    hosts: list[str] = []
    host_configs: dict[str, dict[str, str]] = {}
    current_host: Optional[str] = None
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
        return "~/.ssh/config 中没有配置 Host 别名。"
    # 格式化输出，包含主机详情
    output = ["配置的主机别名："]
    for h in sorted(set(hosts)):
        conf = host_configs.get(h, {})
        info = [h]
        if "hostname" in conf:
            info.append(f"→ {conf.get('user', os.getenv('USERNAME', 'root'))}@{conf['hostname']}:{conf.get('port', '22')}")
        output.append("  " + " ".join(info))
    return "\n".join(output)


def _scan_subnet(cidr: str, port: int, per_host_timeout: float, max_workers: int) -> list[dict]:
    """扫描 CIDR 网段指定端口，返回在线主机列表（含 IP、端口、SSH banner）。"""
    import ipaddress
    import concurrent.futures

    network = ipaddress.ip_network(cidr, strict=False)
    hosts = [str(ip) for ip in network.hosts()]
    results: list[dict] = []

    def probe(ip: str) -> dict | None:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(per_host_timeout)
        try:
            s.connect((ip, port))
            # 尝试读取 SSH banner 识别设备类型
            banner = ""
            if port == 22:
                try:
                    s.settimeout(per_host_timeout)
                    data = s.recv(256)
                    if data:
                        banner = data.decode("utf-8", errors="replace").strip()
                except (socket.timeout, OSError):
                    pass
            return {"ip": ip, "port": port, "banner": banner}
        except (socket.timeout, OSError):
            return None
        finally:
            s.close()

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        for r in ex.map(probe, hosts):
            if r:
                results.append(r)
    return results


@mcp.tool()
def ssh_scan(
    network: str = "192.168.1.0/24",
    port: int = 22,
    timeout: float = 3.0,
    max_workers: int = 100,
    detail: bool = True,
) -> str:
    """扫描局域网网段，发现开放指定端口（默认 SSH 22）的在线主机。

    Args:
        network: CIDR 网段，如 192.168.1.0/24 或 192.168.43.0/24。
        port: 要扫描的端口，默认 22（SSH）。
        timeout: 单台主机探测超时秒数，默认 3.0。无线/高延迟网络建议 5.0+。
        max_workers: 并发扫描线程数，默认 100。/16 大网段建议降到 50。
        detail: 是否尝试获取 SSH banner 识别设备类型，默认 True。

    Returns:
        在线主机列表，包含 IP、端口、SSH banner（如有）。
    """
    t0 = time.monotonic()
    _log.info("ssh_scan_start", network=network, port=port, timeout=timeout)

    try:
        results = _scan_subnet(network, port, timeout, max_workers)
    except ValueError as e:
        _log.warning("ssh_scan_bad_cidr", network=network, error=str(e))
        return f"无效的网段格式：{network}（{e}）"

    elapsed = time.monotonic() - t0
    _log.info("ssh_scan_done", network=network, port=port,
              found=len(results), elapsed=round(elapsed, 3))

    if not results:
        return f"网段 {network} 中未发现开放端口 {port} 的主机（耗时 {round(elapsed, 1)}s）。"

    output = [f"🔍 扫描 {network} 端口 {port}，发现 {len(results)} 台在线主机（耗时 {round(elapsed, 1)}s）："]
    output.append("-" * 70)
    output.append(f"{'序号':<4} {'IP 地址':<18} {'端口':<6} {'SSH Banner / 设备信息'}")
    output.append("-" * 70)
    for i, host in enumerate(sorted(results, key=lambda x: tuple(int(p) for p in x["ip"].split("."))), 1):
        banner = host.get("banner", "") if detail else ""
        output.append(f"{i:<4} {host['ip']:<18} {host['port']:<6} {banner}")
    output.append("-" * 70)
    output.append(f"💡 可使用 ssh_exec 在这些主机上执行命令（如 ssh_exec('user@IP', 'hostname')）")
    return "\n".join(output)


@mcp.tool()
def ssh_upload(host: str, local_path: str, remote_path: str, timeout: int = 60, overwrite: bool = False) -> str:
    """上传本地文件到远程主机。

    Args:
        host: ~/.ssh/config 中的主机别名，或 user@hostname 形式。
        local_path: 本地文件的绝对路径。
        remote_path: 远程主机上的目标路径。
        timeout: 传输超时秒数，默认 60。
        overwrite: 是否允许覆盖系统敏感路径，默认 False。
    """
    local = pathlib.Path(local_path).expanduser().resolve()
    if not local.exists() or not local.is_file():
        raise FileNotFoundError(f"本地文件不存在：{local_path}")
    # 文件大小限制，防止超大文件上传
    size = local.stat().st_size
    if size > 100 * 1024 * 1024:  # 100MB
        raise RuntimeError(f"文件大小超过限制（最大100MB，当前{round(size/1024/1024, 2)}MB）")
    # 敏感路径保护
    if not overwrite and _SENSITIVE_PATHS.search(remote_path):
        _log.warning("upload_to_sensitive_path", remote_path=remote_path)
        raise RuntimeError(f"禁止上传到敏感路径：{remote_path}，如需覆盖请设置 overwrite=True")
    client = _connect(host, timeout=timeout)
    t0 = time.monotonic()
    try:
        sftp = client.open_sftp()
        sftp.put(str(local), remote_path)
        sftp.close()
        elapsed = time.monotonic() - t0
        _log.info("ssh_upload_done", host=host, local_path=str(local), remote_path=remote_path,
                   size=size, elapsed=round(elapsed, 3))
        return f"上传成功：{local_path} → {host}:{remote_path}（{size} 字节，耗时 {round(elapsed, 2)}s）"
    finally:
        client.close()


@mcp.tool()
def ssh_download(host: str, remote_path: str, local_path: str, timeout: int = 60, allow_sensitive: bool = False) -> str:
    """从远程主机下载文件到本地。

    Args:
        host: ~/.ssh/config 中的主机别名，或 user@hostname 形式。
        remote_path: 远程主机上的文件路径。
        local_path: 本地保存的绝对路径。
        timeout: 传输超时秒数，默认 60。
        allow_sensitive: 是否允许下载敏感文件（/etc/shadow、SSH密钥等），默认 False。
    """
    # 敏感文件保护
    if not allow_sensitive and _SENSITIVE_PATHS.search(remote_path):
        _log.warning("download_sensitive_file", remote_path=remote_path)
        raise RuntimeError(f"禁止下载敏感文件：{remote_path}，确认需要请设置 allow_sensitive=True")
    local = pathlib.Path(local_path).expanduser().resolve()
    local.parent.mkdir(parents=True, exist_ok=True)
    client = _connect(host, timeout=timeout)
    t0 = time.monotonic()
    try:
        sftp = client.open_sftp()
        # 检查远程文件大小
        remote_stat = sftp.stat(remote_path)
        if remote_stat.st_size > 100 * 1024 * 1024:  # 100MB
            raise RuntimeError(f"远程文件大小超过限制（最大100MB，当前{round(remote_stat.st_size/1024/1024, 2)}MB）")
        sftp.get(remote_path, str(local))
        sftp.close()
        elapsed = time.monotonic() - t0
        size = local.stat().st_size
        _log.info("ssh_download_done", host=host, remote_path=remote_path, local_path=str(local),
                   size=size, elapsed=round(elapsed, 3))
        return f"下载成功：{host}:{remote_path} → {local_path}（{size} 字节，耗时 {round(elapsed, 2)}s）"
    finally:
        client.close()


@mcp.tool()
def ssh_exec_batch(host: str, commands: list[str], timeout: int = 30, stop_on_error: bool = True) -> str:
    """批量执行多条命令，支持错误中断。

    Args:
        host: ~/.ssh/config 中的主机别名，或 user@hostname 形式。
        commands: 要执行的命令列表。
        timeout: 单条命令超时秒数，默认 30。
        stop_on_error: 遇到错误是否停止执行，默认 True。
    """
    results = []
    for i, cmd in enumerate(commands, 1):
        results.append(f"\n===== 执行第 {i}/{len(commands)} 条命令：{cmd[:80]} =====")
        try:
            res = ssh_exec(host, cmd, timeout=timeout)
            results.append(res)
            if stop_on_error and "[exit_code] 0" not in res.split("\n")[0]:
                results.append(f"\n⚠️ 命令执行失败，停止后续执行")
                break
        except Exception as e:
            results.append(f"执行错误：{str(e)}")
            if stop_on_error:
                results.append(f"\n⚠️ 命令执行异常，停止后续执行")
                break
    return "\n".join(results)


@mcp.tool()
def ssh_list_dir(host: str, remote_path: str = "~", show_hidden: bool = False, timeout: int = 10) -> str:
    """列出远程主机指定目录下的文件和子目录。

    Args:
        host: ~/.ssh/config 中的主机别名，或 user@hostname 形式。
        remote_path: 远程目录路径，默认当前用户家目录 ~。
        show_hidden: 是否显示隐藏文件（.开头的文件），默认 False。
        timeout: 命令超时秒数，默认 10。

    Returns:
        目录列表，包含文件类型、权限、大小、修改时间、文件名。
    """
    # 安全校验：禁止列出敏感目录
    if not show_hidden and _SENSITIVE_PATHS.search(remote_path):
        _log.warning("list_sensitive_dir", path=remote_path)
        raise RuntimeError(f"禁止列出敏感目录：{remote_path}")
    
    # 构建ls命令
    ls_cmd = f"ls -la --time-style=long-iso {shlex.quote(remote_path)}"
    if not show_hidden:
        ls_cmd = f"ls -l --time-style=long-iso {shlex.quote(remote_path)}"
    
    result = ssh_exec(host, ls_cmd, timeout=timeout)
    if "[exit_code] 0" not in result.split("\n")[0]:
        return f"列出目录失败：{result}"
    
    # 解析输出
    lines = result.split("\n")
    output = [f"📂 目录：{remote_path}"]
    output.append("-" * 80)
    output.append(f"{'类型':<3} {'权限':<10} {'大小':<10} {'修改时间':<12} 名称")
    output.append("-" * 80)
    
    for line in lines[2:]:  # 跳过exit_code和stdout行
        if not line.strip():
            continue
        parts = line.split(maxsplit=6)
        if len(parts) < 7:
            continue
        perm = parts[0]
        size = parts[4]
        mtime = f"{parts[5]} {parts[6].split()[0]}"
        name = parts[6] if len(parts) > 6 else ""
        if name in (".", ".."):
            continue
        if not show_hidden and name.startswith("."):
            continue
        # 文件类型标识
        ftype = "📁" if perm.startswith("d") else "📄" if perm.startswith("-") else "🔗" if perm.startswith("l") else "❓"
        # 格式化大小
        try:
            size_num = int(size)
            if size_num < 1024:
                size_str = f"{size_num}B"
            elif size_num < 1024*1024:
                size_str = f"{round(size_num/1024, 1)}KB"
            elif size_num < 1024*1024*1024:
                size_str = f"{round(size_num/1024/1024, 1)}MB"
            else:
                size_str = f"{round(size_num/1024/1024/1024, 2)}GB"
        except:
            size_str = size
        output.append(f"{ftype:<3} {perm:<10} {size_str:<10} {mtime:<12}  {name}")
    
    return "\n".join(output)


@mcp.tool()
def ssh_stat_file(host: str, remote_path: str, timeout: int = 10) -> str:
    """获取远程文件或目录的详细信息。

    Args:
        host: ~/.ssh/config 中的主机别名，或 user@hostname 形式。
        remote_path: 远程文件/目录路径。
        timeout: 命令超时秒数，默认 10。
    """
    result = ssh_exec(host, f"stat {shlex.quote(remote_path)}", timeout=timeout)
    return result


@mcp.tool()
def ssh_mkdir(host: str, remote_path: str, parents: bool = True, timeout: int = 10) -> str:
    """在远程主机创建目录。

    Args:
        host: ~/.ssh/config 中的主机别名，或 user@hostname 形式。
        remote_path: 要创建的目录路径。
        parents: 是否自动创建父目录（类似 mkdir -p），默认 True。
        timeout: 命令超时秒数，默认 10。
    """
    if _SENSITIVE_PATHS.search(remote_path):
        _log.warning("mkdir_sensitive_path", path=remote_path)
        raise RuntimeError(f"禁止在敏感路径创建目录：{remote_path}")
    
    cmd = f"mkdir {'-p' if parents else ''} {shlex.quote(remote_path)}"
    result = ssh_exec(host, cmd, timeout=timeout, allow_dangerous=True)
    if "[exit_code] 0" in result.split("\n")[0]:
        return f"✅ 目录创建成功：{remote_path}"
    return f"❌ 目录创建失败：{result}"


@mcp.tool()
def ssh_remove(host: str, remote_path: str, recursive: bool = False, timeout: int = 30) -> str:
    """删除远程主机上的文件或目录。

    Args:
        host: ~/.ssh/config 中的主机别名，或 user@hostname 形式。
        remote_path: 要删除的文件/目录路径。
        recursive: 是否递归删除目录（类似 rm -rf），默认 False。
        timeout: 命令超时秒数，默认 30。
    """
    if _SENSITIVE_PATHS.search(remote_path):
        _log.warning("remove_sensitive_path", path=remote_path)
        raise RuntimeError(f"禁止删除敏感路径：{remote_path}")
    
    if not recursive:
        cmd = f"rm -f {shlex.quote(remote_path)}"
    else:
        cmd = f"rm -rf {shlex.quote(remote_path)}"
    
    result = ssh_exec(host, cmd, timeout=timeout, allow_dangerous=True)
    if "[exit_code] 0" in result.split("\n")[0]:
        return f"✅ 删除成功：{remote_path}"
    return f"❌ 删除失败：{result}"


@mcp.tool()
def ssh_upload_dir(host: str, local_dir: str, remote_dir: str, overwrite: bool = False, timeout: int = 300) -> str:
    """上传本地目录到远程主机（递归上传所有文件）。

    Args:
        host: ~/.ssh/config 中的主机别名，或 user@hostname 形式。
        local_dir: 本地目录的绝对路径。
        remote_dir: 远程目标目录路径。
        overwrite: 是否允许覆盖系统敏感路径，默认 False。
        timeout: 传输超时秒数，默认 300（5分钟）。
    """
    local = pathlib.Path(local_dir).expanduser().resolve()
    if not local.exists() or not local.is_dir():
        raise FileNotFoundError(f"本地目录不存在：{local_dir}")
    
    if not overwrite and _SENSITIVE_PATHS.search(remote_dir):
        _log.warning("upload_dir_to_sensitive_path", path=remote_dir)
        raise RuntimeError(f"禁止上传到敏感路径：{remote_dir}，如需覆盖请设置 overwrite=True")
    
    client = _connect(host, timeout=timeout)
    t0 = time.monotonic()
    uploaded = 0
    total_size = 0
    
    try:
        sftp = client.open_sftp()
        # 创建远程目录
        try:
            sftp.stat(remote_dir)
        except FileNotFoundError:
            sftp.mkdir(remote_dir)
        
        # 递归上传
        for item in local.rglob("*"):
            rel_path = item.relative_to(local)
            remote_path = f"{remote_dir}/{rel_path.as_posix()}"
            if item.is_dir():
                try:
                    sftp.stat(remote_path)
                except FileNotFoundError:
                    sftp.mkdir(remote_path)
            elif item.is_file():
                size = item.stat().st_size
                if size > 100 * 1024 * 1024:
                    _log.warning("skip_large_file", path=str(item), size=size)
                    continue
                # 确保父目录存在
                remote_parent = str(pathlib.PurePosixPath(remote_path).parent)
                try:
                    sftp.stat(remote_parent)
                except FileNotFoundError:
                    sftp.mkdir(remote_parent)
                sftp.put(str(item), remote_path)
                uploaded += 1
                total_size += size
        
        sftp.close()
        elapsed = time.monotonic() - t0
        _log.info("ssh_upload_dir_done", host=host, local_dir=str(local), remote_dir=remote_dir,
                   files=uploaded, size=total_size, elapsed=round(elapsed, 3))
        return f"✅ 目录上传成功：{local_dir} → {host}:{remote_dir}\n📊 上传文件：{uploaded} 个，总大小：{round(total_size/1024/1024, 2)}MB，耗时：{round(elapsed, 2)}s"
    finally:
        client.close()


@mcp.tool()
def ssh_download_dir(host: str, remote_dir: str, local_dir: str, allow_sensitive: bool = False, timeout: int = 300) -> str:
    """从远程主机下载目录到本地（递归下载所有文件）。

    Args:
        host: ~/.ssh/config 中的主机别名，或 user@hostname 形式。
        remote_dir: 远程目录路径。
        local_dir: 本地保存目录的绝对路径。
        allow_sensitive: 是否允许下载敏感目录，默认 False。
        timeout: 传输超时秒数，默认 300（5分钟）。
    """
    if not allow_sensitive and _SENSITIVE_PATHS.search(remote_dir):
        _log.warning("download_sensitive_dir", path=remote_dir)
        raise RuntimeError(f"禁止下载敏感目录：{remote_dir}，确认需要请设置 allow_sensitive=True")
    
    local = pathlib.Path(local_dir).expanduser().resolve()
    local.mkdir(parents=True, exist_ok=True)
    
    client = _connect(host, timeout=timeout)
    t0 = time.monotonic()
    downloaded = 0
    total_size = 0
    
    try:
        sftp = client.open_sftp()
        
        def _download_dir(remote_path, local_path):
            nonlocal downloaded, total_size
            try:
                sftp.stat(remote_path)
            except FileNotFoundError:
                return
            local_path.mkdir(parents=True, exist_ok=True)
            for item in sftp.listdir_attr(remote_path):
                remote_item = f"{remote_path}/{item.filename}"
                local_item = local_path / item.filename
                if item.st_mode & 0o40000:  # 目录
                    _download_dir(remote_item, local_item)
                elif item.st_mode & 0o100000:  # 文件
                    if item.st_size > 100 * 1024 * 1024:
                        _log.warning("skip_large_remote_file", path=remote_item, size=item.st_size)
                        continue
                    sftp.get(remote_item, str(local_item))
                    downloaded += 1
                    total_size += item.st_size
        
        _download_dir(remote_dir, local)
        sftp.close()
        elapsed = time.monotonic() - t0
        _log.info("ssh_download_dir_done", host=host, remote_dir=remote_dir, local_dir=str(local),
                   files=downloaded, size=total_size, elapsed=round(elapsed, 3))
        return f"✅ 目录下载成功：{host}:{remote_dir} → {local_dir}\n📊 下载文件：{downloaded} 个，总大小：{round(total_size/1024/1024, 2)}MB，耗时：{round(elapsed, 2)}s"
    finally:
        client.close()


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()