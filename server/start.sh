#!/bin/bash
# ============================================================
# VPN 服务端一键启动脚本（多系统兼容版）
# 兼容：Debian/Ubuntu/CentOS/RHEL/Fedora/Arch/OpenWrt 等
# 防火墙：自动选择 iptables / nftables，并补充 ufw / firewalld 放行端口
# 用法：sudo ./start.sh
# 所有配置均可用环境变量覆盖，例如：TUN_IP=10.8.0.1 VPN_PORT=51820 ./start.sh
# ============================================================
set -e

# ===== 可配置项（环境变量可覆盖）=====
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VPN_BIN="${VPN_BIN:-$SCRIPT_DIR/build/vpn_server}"
TUN_NAME="${TUN_NAME:-vpn0}"
TUN_IP="${TUN_IP:-10.8.0.1}"
TUN_PREFIX="${TUN_PREFIX:-24}"
TUN_MTU="${TUN_MTU:-1400}"
TUN_NET="${TUN_NET:-10.8.0.0/24}"
VPN_PORT="${VPN_PORT:-51820}"
LISTEN_IP="${LISTEN_IP:-0.0.0.0}"
KEY_PATH="${KEY_PATH:-$SCRIPT_DIR/keys/server.key}"
ENABLE_IPV6="${ENABLE_IPV6:-0}"        # 1=同时开启 IPv6 转发

# ===== 前置检查 =====
if [ "$(id -u)" -ne 0 ]; then
    echo "[错误] 需要 root 权限运行：sudo $0" >&2
    exit 1
fi
if [ ! -x "$VPN_BIN" ]; then
    echo "[错误] 找不到 vpn_server 可执行文件：$VPN_BIN" >&2
    echo "       请先构建：cmake -S . -B build && cmake --build build" >&2
    exit 1
fi
if [ ! -f "$KEY_PATH" ]; then
    echo "[警告] 未找到服务端私钥：$KEY_PATH（隧道将无法加密）" >&2
    echo "       请把 server.key 放到该路径（用 scp 从本地安全传输）" >&2
fi

# ===== 系统识别 =====
detect_os() {
    if [ -r /etc/os-release ]; then
        . /etc/os-release
        echo "$PRETTY_NAME"
    else
        uname -s -r
    fi
}
echo "[*] 系统: $(detect_os)"

# ===== 1. 内核 IP 转发 =====
echo "[*] 开启 IP 转发"
echo 1 > /proc/sys/net/ipv4/ip_forward
# 持久化：优先 sysctl.d（现代发行版），回退 /etc/sysctl.conf
if [ -d /etc/sysctl.d ]; then
    echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-vpn.conf
else
    grep -q "^net.ipv4.ip_forward" /etc/sysctl.conf 2>/dev/null || \
        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
fi
if [ "$ENABLE_IPV6" = "1" ]; then
    echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
    echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.d/99-vpn.conf
fi

# ===== 2. 检测出口网卡（iproute2，回退 ip addr）=====
detect_iface() {
    local iface
    iface=$(ip route 2>/dev/null | awk '/^default/ {print $5; exit}')
    if [ -z "$iface" ]; then
        iface=$(ip -4 addr show 2>/dev/null | awk '/^[0-9]+:/ {gsub(":","",$2); if ($2!="lo") {print $2; exit}}')
    fi
    [ -z "$iface" ] && iface="eth0"
    echo "$iface"
}
IFACE="${IFACE:-$(detect_iface)}"
echo "[*] 出口网卡: $IFACE"

# ===== 3. 防火墙 / NAT（自动选择 iptables 或 nftables）=====
setup_firewall() {
    # 3.1 优先 iptables（多数系统都有，即使后端是 nft）
    if command -v iptables >/dev/null 2>&1; then
        echo "[*] 使用 iptables 配置 NAT / 转发 / 端口"
        iptables -t nat -C POSTROUTING -s "$TUN_NET" -o "$IFACE" -j MASQUERADE 2>/dev/null || \
            iptables -t nat -A POSTROUTING -s "$TUN_NET" -o "$IFACE" -j MASQUERADE
        iptables -C FORWARD -i "$TUN_NAME" -o "$IFACE" -j ACCEPT 2>/dev/null || \
            iptables -A FORWARD -i "$TUN_NAME" -o "$IFACE" -j ACCEPT
        iptables -C FORWARD -i "$IFACE" -o "$TUN_NAME" -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
            iptables -A FORWARD -i "$IFACE" -o "$TUN_NAME" -m state --state ESTABLISHED,RELATED -j ACCEPT
        iptables -C INPUT -p udp --dport "$VPN_PORT" -j ACCEPT 2>/dev/null || \
            iptables -A INPUT -p udp --dport "$VPN_PORT" -j ACCEPT
        return 0
    fi
    # 3.2 回退 nftables（先删旧表保证幂等）
    if command -v nft >/dev/null 2>&1; then
        echo "[*] 使用 nftables 配置 NAT / 转发 / 端口"
        nft delete table inet vpn 2>/dev/null || true
        nft -f - <<EOF
table inet vpn {
    chain forward {
        type filter hook forward priority 0; policy accept;
        iifname "$TUN_NAME" oifname "$IFACE" accept
        oifname "$TUN_NAME" ct state established,related accept
    }
    chain input {
        type filter hook input priority 0; policy accept;
        udp dport $VPN_PORT accept
    }
    chain postrouting {
        type nat hook postrouting priority 100;
        ip saddr $TUN_NET oifname "$IFACE" masquerade
    }
}
EOF
        return 0
    fi
    echo "[警告] 未找到 iptables / nftables，NAT 可能未生效" >&2
}
setup_firewall

# ===== 4. 补充：ufw / firewalld 放行端口（若存在）=====
if command -v ufw >/dev/null 2>&1; then
    echo "[*] ufw 放行 UDP/$VPN_PORT"
    ufw allow "$VPN_PORT/udp" >/dev/null 2>&1 || true
fi
if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active firewalld >/dev/null 2>&1; then
    echo "[*] firewalld 放行 UDP/$VPN_PORT"
    firewall-cmd --permanent --add-port="$VPN_PORT/udp" >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
fi

# ===== 5. 启动 vpn_server =====
echo "[*] 启动 vpn_server: listen=$LISTEN_IP:$VPN_PORT tun=$TUN_NAME($TUN_IP/$TUN_PREFIX mtu=$TUN_MTU)"
echo "    key=$KEY_PATH"
echo "    [按 Ctrl+C 退出]"
exec "$VPN_BIN" -l "$LISTEN_IP" -p "$VPN_PORT" -n "$TUN_NAME" -a "$TUN_IP" \
    --prefix "$TUN_PREFIX" --mtu "$TUN_MTU" -k "$KEY_PATH"

