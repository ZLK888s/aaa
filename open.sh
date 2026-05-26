#!/usr/bin/env bash
set -Eeuo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "请使用 root 运行此脚本"
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive

cleanup() {
  rm -f /root/ip.sh
}
trap cleanup EXIT

echo "[1/7] 安装基础工具..."
apt-get update --allow-releaseinfo-change
apt-get install -y wget curl screen nload

echo "[2/7] 执行 IP 检测..."
cd /root
wget -O /root/ip.sh https://ip2.ipip.sh/ip.sh
chmod +x /root/ip.sh
bash /root/ip.sh

echo "[3/7] 安装 Docker..."
if ! command -v docker >/dev/null 2>&1; then
  curl -fsSL https://get.docker.com | bash -s docker
else
  echo "Docker 已安装，跳过"
fi

echo "[4/7] 启动 Docker 服务..."
systemctl enable --now docker 2>/dev/null || service docker start

echo "[5/7] 下载镜像包..."
cd /root
wget -O /root/openvpn-v1.tar.gz https://mfdl.sdnlv0.cn/app/openvpn-v1.tar.gz

echo "[6/7] 加载镜像..."
docker load < /root/openvpn-v1.tar.gz

echo "[7/7] 启动 OpenVPN 容器..."
if docker ps -a --format '{{.Names}}' | grep -qx 'openvpn'; then
  echo "检测到已有 openvpn 容器，先删除旧容器..."
  docker rm -f openvpn
fi

docker run \
  --name openvpn \
  --restart=always \
  -p 1194:1194/tcp \
  -d \
  --cap-add=NET_ADMIN \
  --device=/dev/net/tun \
  --sysctl net.ipv4.ip_forward=1 \
  --sysctl net.ipv6.conf.all.forwarding=1 \
  my-openvpn:v1

echo
echo "===== 容器状态检查 ====="
docker ps | grep openvpn

echo
echo "部署完成"
