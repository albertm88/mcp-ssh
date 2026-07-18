"""聚焦搜索：先看目录结构，再针对性找百炼/DashScope 配置。"""
import os
import sys

os.environ["SSH_PASS_192_168_43_123"] = "ubuntu"
sys.path.insert(0, "d:/mcp-ssh")
import server  # noqa: E402

HOST = "ubuntu@192.168.43.123"
T = 30

# Step A: 查看用户主目录结构
print("=" * 60)
print("[A] /home/ubuntu 顶层目录")
print("=" * 60)
print(server.ssh_exec(HOST,
    "ls -la /home/ubuntu/ 2>/dev/null",
    timeout=T))

# Step B: 查看 Desktop / Documents / Projects 等常见位置
print("\n" + "=" * 60)
print("[B] 常见项目子目录")
print("=" * 60)
print(server.ssh_exec(HOST,
    "for d in Desktop Documents Downloads Projects projects work src app; do "
    "  if [ -d \"/home/ubuntu/$d\" ]; then "
    "    echo \"[DIR] /home/ubuntu/$d\"; "
    "    ls -la \"/home/ubuntu/$d\" 2>/dev/null | head -30; "
    "    echo; "
    "  fi; "
    "done",
    timeout=T))

# Step C: shell/env 配置文件中的 API_KEY
print("\n" + "=" * 60)
print("[C] shell & env 配置文件检查")
print("=" * 60)
print(server.ssh_exec(HOST,
    "for f in ~/.bashrc ~/.zshrc ~/.profile ~/.bash_profile ~/.env "
    "~/.config/environment.d/*.conf /etc/environment; do "
    "  if [ -f \"$f\" ]; then "
    "    hits=$(grep -nEi 'dashscope|bailian|api[_-]?key|tts|cosyvoice|sambert|qwen|tongyi' \"$f\" 2>/dev/null); "
    "    if [ -n \"$hits\" ]; then echo \"[FILE] $f\"; echo \"$hits\"; echo; fi; "
    "  fi; "
    "done; echo '[DONE]'",
    timeout=T))

# Step D: systemd 服务配置（机器人/语音服务可能在这里）
print("\n" + "=" * 60)
print("[D] systemd 用户/系统服务含 dashscope/bailian/tts 关键字")
print("=" * 60)
print(server.ssh_exec(HOST,
    "grep -rliE 'dashscope|bailian|cosyvoice|sambert|tts|qwen' "
    "/etc/systemd/system ~/.config/systemd/user 2>/dev/null | head -20; "
    "echo '[DONE]'",
    timeout=T))

# Step E: 聚焦搜索常见项目目录（不扫全盘）
print("\n" + "=" * 60)
print("[E] 项目目录内搜索 dashscope/bailian")
print("=" * 60)
print(server.ssh_exec(HOST,
    "grep -rliE 'dashscope|bailian|DASHSCOPE_API_KEY' "
    "--exclude-dir=.git --exclude-dir=node_modules --exclude-dir=.venv "
    "--exclude-dir=__pycache__ --exclude-dir=.cache "
    "--include='*.py' --include='*.yaml' --include='*.yml' "
    "--include='*.json' --include='*.toml' --include='*.env' "
    "--include='*.conf' --include='*.sh' --include='*.md' --include='*.txt' "
    "/home/ubuntu 2>/dev/null | head -50; echo '[DONE]'",
    timeout=120))
