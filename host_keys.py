"""Strict host-key identity boundary for SSH connections.

Replaces the previous silent AutoAddPolicy behaviour: unknown or mismatched
host keys fail closed (HOST_KEY_MISMATCH) before any remote side effect.
Trusted keys come only from the system known_hosts file and/or an explicit
SSH_KNOWN_HOSTS file. There is deliberately no auto-accept path.
"""
from __future__ import annotations

import os
import pathlib
import platform

import paramiko


class HostKeyError(Exception):
    """Raised when the remote host key is unknown or mismatched."""

    def __init__(self, message: str, hostname: str = "", port: int = 0) -> None:
        super().__init__(message)
        self.hostname = hostname
        self.port = port


def _ssh_dir() -> pathlib.Path:
    if platform.system() == "Windows":
        return pathlib.Path(os.environ.get("USERPROFILE", pathlib.Path.home()))
    return pathlib.Path.home()


def _system_known_hosts_path() -> pathlib.Path:
    return _ssh_dir() / ".ssh" / "known_hosts"


def load_known_hosts_files() -> list[pathlib.Path]:
    """Return trusted known_hosts files: explicit SSH_KNOWN_HOSTS, then system.

    Missing or unreadable files are omitted; the caller must fail closed when
    the resulting list is empty.
    """
    files: list[pathlib.Path] = []
    explicit = os.getenv("SSH_KNOWN_HOSTS")
    if explicit:
        p = pathlib.Path(explicit).expanduser()
        if p.is_file():
            files.append(p)
    system = _system_known_hosts_path()
    if system.is_file():
        files.append(system)
    return files


def has_trusted_known_hosts() -> bool:
    """True only when at least one readable trusted source exists."""
    return bool(load_known_hosts_files())


def apply_host_key_policy(
    client: paramiko.SSHClient,
    hostname: str,
    port: int,
) -> None:
    """Load trusted host keys and set the reject policy on the client.

    Raises:
        RuntimeError: no trusted known_hosts source exists (fail closed).
    """
    if not has_trusted_known_hosts():
        raise RuntimeError(
            "没有可用的 known_hosts 可信来源：请配置 SSH_KNOWN_HOSTS "
            "或系统 ~/.ssh/known_hosts 后重试，禁止自动信任未知主机密钥。"
        )
    try:
        client.load_system_host_keys()
    except (OSError, paramiko.SSHException):
        pass
    for path in load_known_hosts_files():
        try:
            client.load_host_keys(str(path))
        except (OSError, paramiko.SSHException):
            pass
    client.set_missing_host_key_policy(paramiko.RejectPolicy())


def is_host_key_failure(error: Exception) -> bool:
    """True when the exception indicates an unknown or mismatched host key.

    paramiko raises BadHostKeyException on mismatch and an SSHException
    containing 'not found in known_hosts' on unknown keys.
    """
    if isinstance(error, paramiko.BadHostKeyException):
        return True
    if isinstance(error, paramiko.SSHException):
        text = str(error).lower()
        return "known_hosts" in text and "not found" in text
    return False


def host_key_mismatch_message(hostname: str, port: int, error: Exception) -> str:
    """Build a redacted diagnostic for host-key failures.

    Never includes passwords, private keys, or environment values.
    """
    detail = ""
    if isinstance(error, paramiko.BadHostKeyException):
        detail = "指纹与 known_hosts 记录不匹配"
    else:
        detail = "主机密钥未知，未在 known_hosts 中找到对应条目"
    return (
        f"主机密钥校验失败：{hostname}:{port} —— {detail}。"
        f"请在 SSH 配置层显式信任该指纹后重试，禁止自动接受未知密钥。"
    )
