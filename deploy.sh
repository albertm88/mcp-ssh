#!/bin/bash
# MediaMTX 一键部署脚本
# 使用方法：
# 1. 下载mediamtx二进制到当前目录：wget https://github.com/bluenviron/mediamtx/releases/download/v1.9.3/mediamtx_v1.9.3_linux_amd64.tar.gz
# 2. 解压：tar -xzf mediamtx_v1.9.3_linux_amd64.tar.gz
# 3. 运行本脚本：bash deploy.sh

set -e

echo "=== MediaMTX 部署开始 ==="

# 创建目录
mkdir -p /opt/mediamtx /opt/mediamtx-recordings
cp mediamtx /opt/mediamtx/
chmod +x /opt/mediamtx/mediamtx

# 复制配置文件
cp mediamtx.yml /opt/mediamtx/

# 安装systemd服务
cp mediamtx.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable mediamtx
systemctl start mediamtx

# 开放防火墙端口
if command -v ufw &> /dev/null; then
    ufw allow 8554/tcp
    ufw allow 1935/tcp
    ufw allow 8888/tcp
    ufw allow 8889/tcp
    ufw allow 9997/tcp
    ufw reload
fi

echo "=== 部署完成 ==="
echo "服务状态："
systemctl status mediamtx --no-pager
echo ""
echo "RTSP流地址：rtsp://服务器IP:8554/dog"
echo "RTMP流地址：rtmp://服务器IP:1935/dog"
echo "HLS流地址：http://服务器IP:8888/dog/index.m3u8"
echo "WebRTC流地址：http://服务器IP:8889/dog"
echo "API地址：http://服务器IP:9997"
echo ""
echo "配置文件路径：/opt/mediamtx/mediamtx.yml"
echo "录像存储路径：/opt/mediamtx-recordings/"
echo "查看日志：journalctl -u mediamtx -f"
