#pragma once

#include <string>
#include <thread>
#include <atomic>
#include <cstdint>
#include <cstddef>

#include "../tun/tun.h"
#include "../UDP/UDP.h"
#include "../LinuxAdapter/LinuxAdapter.h"

// VPN 核心（服务端）：把 TUN 虚拟网卡与 UDP 隧道桥接起来。
// 转发层两条数据通路：
//   1) tun → UDP : forward_tun_to_udp() 线程循环 tun.read_buf() 读到 IP 包
//                  → udp.send_ip_packet() 推入发送队列，由 UDP.send_thread 封装隧道头发给对端
//   2) UDP → tun : forward_udp_to_tun() 线程循环 udp.recv_ip_packet() 从接收队列取出
//                  → tun.write_buf() 写入虚拟网卡
// 生命周期：init(建TUN+配地址+启动UDP收发线程) → start(启动转发线程) → stop(停止+清理)
class VpnCore
{
public:
    struct Config
    {
        // TUN 网卡
        std::string tun_name = "vpn0";
        std::string tun_ip;             // 隧道内网 IP，如 10.8.0.1
        int tun_prefix = 24;
        int tun_mtu = 1400;
        bool add_default_route = false; // 是否把默认路由指向 TUN

        // 服务端监听配置
        std::string listen_ip = "0.0.0.0";
        uint16_t listen_port = 51820;

        // 加密：服务端 X25519 私钥 (PEM)
        std::string key_path = "keys/server.key";
    };

public:
    VpnCore() = default;
    ~VpnCore();

    VpnCore(const VpnCore&) = delete;
    VpnCore &operator=(const VpnCore&) = delete;

    // 初始化：建 TUN → 配置地址/MTU/up →（可选）路由 → udp.start() 启动收发线程
    bool init(const Config &cfg);
    // 启动 TUN↔UDP 两条转发线程（转发层）
    bool start();
    // 停止全部并清理：停转发线程、udp.stop()、down 网卡、删路由
    void stop();
    bool is_running() const;

private:
    // ===== 转发层 =====
    void forward_tun_to_udp();     // 通读TUN: 读 IP 包 → udp.send_ip_packet()
    void forward_udp_to_tun();     // 通读UDP: udp.recv_ip_packet() → tun.write_buf()

private:
    Config m_cfg;
    Tun m_tun;                     // 虚拟网卡
    UDP m_udp;                     // UDP 隧道（服务端：绑定监听）
    LinuxAdapter m_adapter;        // 系统网卡配置（IP/MTU/路由）
    std::thread m_thread_t2u;      // 转发线程1: tun → udp
    std::thread m_thread_u2t;      // 转发线程2: udp → tun
    std::atomic<bool> m_running{false};
    bool m_tun_ready{false};       // TUN 是否已成功创建（控制网卡清理）
};
