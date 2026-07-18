"""读取 claw_tts.py 完整内容 + claw_voice.py + TTS launch 配置。"""
import os
import sys

os.environ["SSH_PASS_192_168_43_123"] = "ubuntu"
sys.path.insert(0, "d:/mcp-ssh")
import server  # noqa: E402

HOST = "ubuntu@192.168.43.123"
T = 30

def run(cmd, timeout=T):
    return server.ssh_exec(HOST, cmd, timeout=timeout)

# 1) claw_tts.py 完整内容
print("=" * 60)
print("[1] claw_tts.py 完整内容")
print("=" * 60)
print(run("cat /home/ubuntu/ros2_ws/src/openclaw_controller/openclaw_controller/claw_tts.py"))

# 2) claw_voice.py 完整内容（可能含 LLM + TTS API 调用）
print("\n" + "=" * 60)
print("[2] claw_voice.py 完整内容")
print("=" * 60)
print(run("cat /home/ubuntu/ros2_ws/src/openclaw_controller/openclaw_controller/claw_voice.py"))

# 3) TTS launch 配置
print("\n" + "=" * 60)
print("[3] claw_tts.launch.py")
print("=" * 60)
print(run("cat /home/ubuntu/ros2_ws/src/openclaw_controller/launch/include/claw_tts.launch.py 2>/dev/null"))

# 4) openclaw_controller config 目录
print("\n" + "=" * 60)
print("[4] openclaw_controller/config 目录")
print("=" * 60)
print(run("ls -la /home/ubuntu/ros2_ws/src/openclaw_controller/config/ 2>/dev/null"))
print(run("find /home/ubuntu/ros2_ws/src/openclaw_controller/config -type f 2>/dev/null | head -20"))
