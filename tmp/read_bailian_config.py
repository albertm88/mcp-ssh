"""读取百炼 LLM/TTS 关键配置文件内容。"""
import os
import sys

os.environ["SSH_PASS_192_168_43_123"] = "ubuntu"
sys.path.insert(0, "d:/mcp-ssh")
import server  # noqa: E402

HOST = "ubuntu@192.168.43.123"
T = 30

def run(cmd, timeout=T):
    return server.ssh_exec(HOST, cmd, timeout=timeout)

# 1) /home/ubuntu/large_models/config.py - 核心配置文件
print("=" * 60)
print("[1] /home/ubuntu/large_models/config.py")
print("=" * 60)
print(run("cat /home/ubuntu/large_models/config.py"))

# 2) ros2_ws/src/large_models 目录结构 + 配置文件
print("\n" + "=" * 60)
print("[2] ros2_ws/src/large_models 结构")
print("=" * 60)
print(run("find /home/ubuntu/ros2_ws/src/large_models -maxdepth 3 -type f "
          "-name '*.py' -o -name '*.yaml' -o -name '*.yml' -o -name '*.json' -o -name '*.env' 2>/dev/null | head -40"))

# 3) ros2_ws/src/large_models 下的 config 文件
print("\n" + "=" * 60)
print("[3] ros2_ws/src/large_models 配置文件位置")
print("=" * 60)
print(run("find /home/ubuntu/ros2_ws/src/large_models -maxdepth 4 "
          "\\( -name 'config*.py' -o -name '*.yaml' -o -name '*.yml' -o -name '*.env' -o -name '*.json' \\) "
          "-type f 2>/dev/null"))

# 4) 用 grep 搜索 large_models 包内 dashscope/api_key 关键字位置（不使用 $() ）
print("\n" + "=" * 60)
print("[4] grep dashscope/api_key 在 ros2_ws/src/large_models 的位置")
print("=" * 60)
print(run("grep -rnE 'dashscope|DASHSCOPE_API_KEY|api_key|API_KEY' "
          "--include='*.py' --include='*.yaml' --include='*.yml' --include='*.json' --include='*.env' "
          "/home/ubuntu/ros2_ws/src/large_models 2>/dev/null | head -60"))

# 5) grep tts 相关
print("\n" + "=" * 60)
print("[5] grep tts/voice/cosyvoice/sambert 在 ros2_ws/src/large_models")
print("=" * 60)
print(run("grep -rnEi 'tts|cosyvoice|sambert|voice|speech|qwen' "
          "--include='*.py' --include='*.yaml' --include='*.yml' --include='*.json' --include='*.env' "
          "/home/ubuntu/ros2_ws/src/large_models 2>/dev/null | head -60"))

# 6) 查看主目录 .env 文件（如果有）
print("\n" + "=" * 60)
print("[6] 查找所有 .env 文件")
print("=" * 60)
print(run("find /home/ubuntu -maxdepth 4 -name '.env*' -type f 2>/dev/null | head -20"))

# 7) bashrc / zshrc 全文（查看环境变量）
print("\n" + "=" * 60)
print("[7] ~/.bashrc 中含 export/KEY 的行")
print("=" * 60)
print(run("grep -nE 'export|KEY|key|API|api|dashscope|bailian|qwen' /home/ubuntu/.bashrc 2>/dev/null | head -40"))
