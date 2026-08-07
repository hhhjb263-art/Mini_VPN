#include "VpnCore.h"
#include "../Crypt/crypt.h"

#include <cstdio>
#include <cstring>
#include <cerrno>
#include <system_error>
#include <chrono>
#include <thread>

// 数据包级日志开关（与 UDP.cpp 保持一致）
#ifndef VPN_PACKET_LOG
#define VPN_PACKET_LOG 1
#endif

VpnCore::~VpnCore()
{
    stop();
}

bool VpnCore::init(const Config &cfg)
{
    if(is_running()){
        return true;   // 已在运行
    }
    m_cfg = cfg;

    // 1) 创建 TUN 虚拟网卡（非阻塞）
    if(!m_tun.create_tun(m_cfg.tun_name.c_str())){
        fprintf(stderr, "[VpnCore] create_tun(%s) failed\n", m_cfg.tun_name.c_str());
        return false;
    }
    m_tun_ready = true;
    m_tun.setNoBlock();

    // 2) 配置网卡地址 / 掩码 / MTU / up
    if(!m_cfg.tun_ip.empty()){
        if(!m_adapter.set_address(m_cfg.tun_name, m_cfg.tun_ip, m_cfg.tun_prefix)){
            fprintf(stderr, "[VpnCore] set_address(%s, %s/%d) failed\n",
                    m_cfg.tun_name.c_str(), m_cfg.tun_ip.c_str(), m_cfg.tun_prefix);
            return false;
        }
    }
    if(!m_adapter.set_mtu(m_cfg.tun_name, m_cfg.tun_mtu)){
        fprintf(stderr, "[VpnCore] set_mtu(%s, %d) failed\n",
                m_cfg.tun_name.c_str(), m_cfg.tun_mtu);
        return false;
    }
    if(!m_adapter.set_up(m_cfg.tun_name)){
        fprintf(stderr, "[VpnCore] set_up(%s) failed\n", m_cfg.tun_name.c_str());
        return false;
    }

    // 3) 可选：把默认路由指向 TUN
    if(m_cfg.add_default_route){
        if(!m_adapter.route_add("0.0.0.0", 0, m_cfg.tun_name)){
            fprintf(stderr, "[VpnCore] route_add(0.0.0.0/0 -> %s) failed\n",
                    m_cfg.tun_name.c_str());
            return false;
        }
    }

    // 4) 加载服务端 X25519 私钥（加密隧道）
    if(!m_cfg.key_path.empty()){
        try {
            EVP_PKEY *priv = load_x25519_private_key(m_cfg.key_path.c_str());
            m_udp.set_credentials(std::shared_ptr<EVP_PKEY>(priv, EVP_PKEY_free));
            fprintf(stderr, "[VpnCore] 已加载服务端私钥: %s\n", m_cfg.key_path.c_str());
        } catch(const std::exception &e){
            fprintf(stderr, "[VpnCore] 加载私钥 %s 失败: %s\n", m_cfg.key_path.c_str(), e.what());
            stop();
            return false;
        }
    } else {
        fprintf(stderr, "[VpnCore] 警告: 未配置私钥，隧道不加密\n");
    }

    // 5) 启动 UDP 隧道（服务端绑定监听）
    if(!m_udp.start(m_cfg.listen_ip, m_cfg.listen_port)){
        fprintf(stderr, "[VpnCore] udp.start(%s:%u) failed\n",
                m_cfg.listen_ip.c_str(), m_cfg.listen_port);
        stop();
        return false;
    }
    return true;
}

bool VpnCore::start()
{
    if(is_running()){
        return true;
    }
    m_running.store(true);
    try{
        m_thread_t2u = std::thread(&VpnCore::forward_tun_to_udp, this);
        m_thread_u2t = std::thread(&VpnCore::forward_udp_to_tun, this);
    }catch(const std::system_error &e){
        fprintf(stderr, "[VpnCore] start forward threads failed: %s\n", e.what());
        m_running.store(false);
        if(m_thread_t2u.joinable()){
            m_thread_t2u.join();
        }
        if(m_thread_u2t.joinable()){
            m_thread_u2t.join();
        }
        return false;
    }
    return true;
}

void VpnCore::stop()
{
    // 停止转发线程
    m_running.store(false);
    if(m_thread_t2u.joinable()){
        m_thread_t2u.join();
    }
    if(m_thread_u2t.joinable()){
        m_thread_u2t.join();
    }
    // 停止 UDP 收发线程
    m_udp.stop();
    // 清理路由与网卡（仅在 TUN 创建成功后才做网卡操作）
    if(m_cfg.add_default_route){
        m_adapter.route_del("0.0.0.0", 0);
    }
    if(m_tun_ready){
        m_adapter.set_down(m_cfg.tun_name);
    }
    // 关闭 TUN
    m_tun.close();
}

bool VpnCore::is_running() const
{
    return m_running.load();
}

// ===== 转发层 =====

// tun → UDP：读虚拟网卡上的 IP 包，推入 UDP 发送队列
void VpnCore::forward_tun_to_udp()
{
    packet_buffer buf;
    while(m_running.load()){
        if(m_tun.read_buf(buf)){
            if(!buf.is_empty()){
#if VPN_PACKET_LOG
                fprintf(stderr, "[CORE][TUN→UDP] len=%zu\n", buf.data_size());
#endif
                m_udp.send_ip_packet(std::move(buf));
            }
        } else {
            // TUN 无数据（非阻塞 EAGAIN），短暂休眠避免忙轮询
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }
}

// UDP → tun：从 UDP 接收队列取 IP 包，写入虚拟网卡
void VpnCore::forward_udp_to_tun()
{
    packet_buffer buf;
    while(m_running.load()){
        if(m_udp.recv_ip_packet(buf)){
            if(!buf.is_empty()){
#if VPN_PACKET_LOG
                fprintf(stderr, "[CORE][UDP→TUN] len=%zu\n", buf.data_size());
#endif
                m_tun.write_buf(buf);
            }
        } else {
            // UDP 接收队列空，短暂休眠
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }
}
