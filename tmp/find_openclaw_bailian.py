"""搜索 openclaw 项目使用的阿里云百炼 LLM 和单独 TTS API 配置。"""
import os
import sys

os.environ["SSH_PASS_192_168_43_123"] = "ubuntu"
sys.path.insert(0, "d:/mcp-ssh")
import server  # noqa: E402

HOST = "ubuntu@192.168.43.123"
T = 30

def run(cmd, timeout=T):
    return server.ssh_exec(HOST, cmd, timeout=timeout)

# 1) 查看 openclaw 相关目录结构
print("=" * 60)
print("[1] openclaw 相关目录")
print("=" * 60)
print(run("ls -la /home/ubuntu/.openclaw/ 2>/dev/null"))
print(run("ls -la /home/ubuntu/openclaw_resource/ 2>/dev/null"))
print(run("ls -la /home/ubuntu/ros2_ws/src/openclaw_controller/ 2>/dev/null"))

# 2) grep 搜索 openclaw 相关目录里的 dashscope/bailian/api_key
print("\n" + "=" * 60)
print("[2] grep dashscope/api_key 在 openclaw 目录")
print("=" * 60)
print(run("grep -rliE 'dashscope|bailian|DASHSCOPE_API_KEY|api_key|API_KEY' "
          "--exclude-dir=.git --exclude-dir=node_modules --exclude-dir=.venv "
          "--exclude-dir=__pycache__ --exclude-dir=.cache --exclude-dir=build "
          "--include='*.py' --include='*.yaml' --include='*.yml' "
          "--include='*.json' --include='*.toml' --include='*.env' "
          "--include='*.conf' --include='*.sh' --include='*.cfg' --include='*.ini' "
          "--include='*.md' --include='*.txt' "
          "/home/ubuntu/.openclaw /home/ubuntu/openclaw_resource "
          "/home/ubuntu/ros2_ws/src/openclaw_controller 2>/dev/null | head -60"))

# 3) grep 搜索 TTS 相关
print("\n" + "=" * 60)
print("[3] grep tts/cosyvoice/sambert/voice/speech 在 openclaw 目录")
print("=" * 60)
print(run("grep -rliE 'tts|cosyvoice|sambert|voice|speech|qwen|tongyi' "
          "--exclude-dir=.git --exclude-dir=node_modules --exclude-dir=.venv "
          "--exclude-dir=__pycache__ --exclude-dir=.cache --exclude-dir=build "
          "--include='*.py' --include='*.yaml' --include='*.yml' "
          "--include='*.json' --include='*.toml' --include='*.env' "
          "--include='*.conf' --include='*.sh' --include='*.cfg' --include='*.ini' "
          "/home/ubuntu/.openclaw /home/ubuntu/openclaw_resource "
          "/home/ubuntu/ros2_ws/src/openclaw_controller 2>/dev/null | head -60"))
