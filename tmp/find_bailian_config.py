"""搜索 192.168.43.123 上阿里云百炼 DashScope 的 LLM/TTS API 配置信息。"""
import os
import sys
import json

os.environ["SSH_PASS_192_168_43_123"] = "ubuntu"
sys.path.insert(0, "d:/mcp-ssh")
import server  # noqa: E402

HOST = "ubuntu@192.168.43.123"
# 无线网络延迟较高（平均 214ms，峰值 445ms），加大超时
TIMEOUT = 30

# Step 1: 连通性自检
print("=" * 60)
print("[Step 1] 连通性自检")
print("=" * 60)
print(server.ssh_exec(HOST, "hostname; whoami; uname -a; date", timeout=TIMEOUT))

# Step 2: 搜索常见配置文件关键词
# 阿里云百炼 / DashScope 关键词：DASHSCOPE_API_KEY / dashscope / bailian / api-key
# TTS 关键词：tts / speech / voice / CosyVoice / sambert
print("\n" + "=" * 60)
print("[Step 2] 搜索 DashScope/百炼 相关配置文件（排除噪音目录）")
print("=" * 60)
search_cmd = (
    "grep -rliE 'dashscope|bailian|DASHSCOPE_API_KEY' "
    "--exclude-dir=.vscode-server --exclude-dir=.cache "
    "--exclude-dir=node_modules --exclude-dir=.git "
    "--exclude-dir=.npm --exclude-dir=.local --exclude-dir=site-packages "
    "--exclude-dir=__pycache__ --exclude='*.pyc' "
    "/home/ubuntu 2>/dev/null | head -50"
)
print(server.ssh_exec(HOST, search_cmd, timeout=90))

# Step 3: 搜索环境变量配置文件 (.bashrc / .zshrc / .profile / .env)
print("\n" + "=" * 60)
print("[Step 3] 检查 shell 配置与环境变量文件")
print("=" * 60)
shell_cmd = (
    "for f in ~/.bashrc ~/.zshrc ~/.profile ~/.bash_profile ~/.env; do "
    "  if [ -f \"$f\" ]; then "
    "    echo \"[FILE] $f\"; "
    "    grep -nE 'dashscope|bailian|DASHSCOPE|API_KEY|api-key' \"$f\" 2>/dev/null; "
    "  fi; "
    "done"
)
print(server.ssh_exec(HOST, shell_cmd, timeout=TIMEOUT))

# Step 4: 检查当前进程环境变量是否含 DASHSCOPE
print("\n" + "=" * 60)
print("[Step 4] 当前会话环境变量检查")
print("=" * 60)
print(server.ssh_exec(HOST, "env | grep -iE 'dashscope|bailian' || echo '[无相关环境变量]'", timeout=TIMEOUT))

# Step 5: 查找 TTS 相关配置
print("\n" + "=" * 60)
print("[Step 5] 搜索 TTS 相关配置（CosyVoice/sambert/voice/speech）")
print("=" * 60)
tts_cmd = (
    "grep -rliE 'cosyvoice|sambert|tts|speech-synthesis|voice-id' "
    "--exclude-dir=.vscode-server --exclude-dir=.cache "
    "--exclude-dir=node_modules --exclude-dir=.git "
    "--exclude-dir=.npm --exclude-dir=.local --exclude-dir=site-packages "
    "--exclude-dir=__pycache__ --exclude='*.pyc' "
    "/home/ubuntu 2>/dev/null | head -50"
)
print(server.ssh_exec(HOST, tts_cmd, timeout=90))
