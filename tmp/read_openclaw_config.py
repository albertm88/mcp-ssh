"""读取 openclaw 的百炼 LLM 和 TTS 配置文件完整内容。"""
import os
import sys

os.environ["SSH_PASS_192_168_43_123"] = "ubuntu"
sys.path.insert(0, "d:/mcp-ssh")
import server  # noqa: E402

HOST = "ubuntu@192.168.43.123"
T = 30

def run(cmd, timeout=T):
    return server.ssh_exec(HOST, cmd, timeout=timeout)

# 1) openclaw.json 主配置
print("=" * 60)
print("[1] /home/ubuntu/.openclaw/openclaw.json")
print("=" * 60)
print(run("cat /home/ubuntu/.openclaw/openclaw.json"))

# 2) models.json (LLM 模型配置)
print("\n" + "=" * 60)
print("[2] /home/ubuntu/.openclaw/agents/main/agent/models.json")
print("=" * 60)
print(run("cat /home/ubuntu/.openclaw/agents/main/agent/models.json"))

# 3) auth-profiles.json (认证 profile)
print("\n" + "=" * 60)
print("[3] /home/ubuntu/.openclaw/agents/main/agent/auth-profiles.json")
print("=" * 60)
print(run("cat /home/ubuntu/.openclaw/agents/main/agent/auth-profiles.json"))

# 4) claw_tts.py - openclaw TTS 节点
print("\n" + "=" * 60)
print("[4] ros2_ws/src/openclaw_controller/openclaw_controller/claw_tts.py")
print("=" * 60)
print(run("cat /home/ubuntu/ros2_ws/src/openclaw_controller/openclaw_controller/claw_tts.py"))

# 5) claw_voice.py - 语音交互节点（可能含 LLM 调用）
print("\n" + "=" * 60)
print("[5] ros2_ws/src/openclaw_controller/openclaw_controller/claw_voice.py (前 120 行)")
print("=" * 60)
print(run("head -120 /home/ubuntu/ros2_ws/src/openclaw_controller/openclaw_controller/claw_voice.py"))

# 6) agents 目录结构
print("\n" + "=" * 60)
print("[6] .openclaw/agents 目录结构")
print("=" * 60)
print(run("find /home/ubuntu/.openclaw/agents -maxdepth 4 -type f 2>/dev/null | head -40"))
