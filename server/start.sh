#!/bin/bash
# ============================================================
# VPN 服务端一键启动脚本
# 用法：sudo ./start.sh
# 作用：启动前自动配置 内核转发 + NAT + 防火墙放行，然后运行 vpn_server
# ============================================================
set -e

# ===== 可配置项（按需修改）=====
VPN_BIN="/home/user/vscode/build/vpn_server"
TUN_NAME="vpn0"              # TUN 网卡名
TUN_IP="10.8.0.1"            # 隧道内网 IP
TUN_NET="10.8.0.0/24"        # 隧道网段
VPN_PORT="51820"             # UDP 端口
LISTEN_IP="0.0.0.0"

# ===== 自动获取出口网卡 =====
IFACE=$(ip route | awk '/default/ {print $5; exit}')
echo "[*] 出口网卡: $IFACE"

# ===== 1. 内核 IP 转发 =====
echo "[*] 开启 IP 转发"
echo 1 > /proc/sys/net/ipv4/ip_forward
grep -q "net.ipv4.ip_forward" /etc/sysctl.conf 2>/dev/null || \
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf

# ===== 2. NAT 伪装：客户端流量以服务器 IP 上网 =====
echo "[*] 配置 NAT (MASQUERADE)"
iptables -t nat -C POSTROUTING -s "$TUN_NET" -o "$IFACE" -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -s "$TUN_NET" -o "$IFACE" -j MASQUERADE

# ===== 3. 放行 FORWARD 转发 =====
echo "[*] 放行 FORWARD"
iptables -C FORWARD -i "$TUN_NAME" -o "$IFACE" -j ACCEPT 2>/dev/null || \
    iptables -A FORWARD -i "$TUN_NAME" -o "$IFACE" -j ACCEPT
iptables -C FORWARD -i "$IFACE" -o "$TUN_NAME" -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
    iptables -A FORWARD -i "$IFACE" -o "$TUN_NAME" -m state --state ESTABLISHED,RELATED -j ACCEPT

# ===== 4. 放行 UDP 端口 =====
echo "[*] 放行 UDP/$VPN_PORT"
iptables -C INPUT -p udp --dport "$VPN_PORT" -j ACCEPT 2>/dev/null || \
    iptables -A INPUT -p udp --dport "$VPN_PORT" -j ACCEPT

# ===== 5. 启动 vpn_server =====
echo "[*] 启动 vpn_server: listen=$LISTEN_IP:$VPN_PORT tun=$TUN_NAME($TUN_IP)"
echo "[*] 按 Ctrl+C 退出"
exec "$VPN_BIN" -l "$LISTEN_IP" -p "$VPN_PORT" -n "$TUN_NAME" -a "$TUN_IP" --prefix 24
