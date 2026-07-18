"""读取 ROS2 large_models 包的 config.py 完整内容 + tts_node.py 头部。"""
import os
import sys

os.environ["SSH_PASS_192_168_43_123"] = "ubuntu"
sys.path.insert(0, "d:/mcp-ssh")
import server  # noqa: E402

HOST = "ubuntu@192.168.43.123"

print("=" * 60)
print("[A] ros2_ws/src/large_models/large_models/large_models/config.py 完整内容")
print("=" * 60)
print(server.ssh_exec(HOST,
    "cat /home/ubuntu/ros2_ws/src/large_models/large_models/large_models/config.py",
    timeout=30))

print("\n" + "=" * 60)
print("[B] tts_node.py 前 80 行")
print("=" * 60)
print(server.ssh_exec(HOST,
    "head -80 /home/ubuntu/ros2_ws/src/large_models/large_models/large_models/tts_node.py",
    timeout=30))

print("\n" + "=" * 60)
print("[C] agent_process.py 前 75 行（看 LLM 客户端初始化）")
print("=" * 60)
print(server.ssh_exec(HOST,
    "head -75 /home/ubuntu/ros2_ws/src/large_models/large_models/large_models/agent_process.py",
    timeout=30))

print("\n" + "=" * 60)
print("[D] speech_pkg 目录结构（看是否有本地 TTS 引擎封装）")
print("=" * 60)
print(server.ssh_exec(HOST,
    "ls -la /home/ubuntu/large_models/speech_pkg/ 2>/dev/null",
    timeout=30))
