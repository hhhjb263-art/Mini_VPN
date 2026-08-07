#pragma once

#include "tunnel_protoco.h"
#include "PacketQueue.h"
#include "Crypt.h"

#include <atomic>
#include <memory>
#include <thread>
#include <vector>


class UDP{
public:
    UDP(
        const char* remoteip,
        uint16_t port,
        bool is_running = false,
        size_t queueMax = 4096
    );
    ~UDP();
    bool init();
    void stop();
    // ---- 重连状态机查询接口 ----
    bool is_handshaked() const { return m_handshaked.load(); }
    bool needs_reconnect() const { return m_need_reconnect.load(); }
    int64_t last_rx_ms() const { return m_last_rx_ms.load(); }
    void send_ip_packet(
        packet_buffer&& buf
    );
    bool recv_ip_packet(packet_buffer& buf);
    bool try_recv_ip_packet(packet_buffer& buf); // 非阻塞接收（轮询/测试用）
    bool send_packet(uint8_t type,
        const uint8_t* data,
        size_t len,
        std::vector<uint8_t>& sendbuf);

    // 配置 X25519 密钥：客户端传 (私钥, 服务器公钥)，服务端角色传 (私钥, 客户端公钥)
    void set_credentials(
        std::shared_ptr<EVP_PKEY> priv_key,
        std::shared_ptr<EVP_PKEY> peer_pub_key);
    uint32_t GenerateISN();
public:
    void send_work();
    void recv_work();
private:
    SOCKET m_sock;
    sockaddr_in m_sockaddr{};
    PacketQueue m_sendqueue;
    PacketQueue m_recvqueue;
    std::thread send_thread;
    std::thread recv_thread;
    std::atomic<bool> m_running{ false };
    std::atomic<bool> m_handshaked{ false };
    std::atomic<bool> m_need_reconnect{ false };
    std::atomic<uint32_t> m_seq{ 0 };
	std::atomic<int64_t> m_last_rx_ms{ 0 };	// 最近一次收到合法报文的时间（steady_clock ms）
    HandshakeState m_hs_state = HS_IDLE;
    uint32_t m_client_isn = 0;    // 客户端随机初始序列号（模仿TCP ISN）
    uint32_t m_server_isn = 0;

    // ============ 加密状态（X25519 + AES-256-GCM） ============
    std::shared_ptr<EVP_PKEY> m_priv_key;       // 自己的 X25519 私钥
    std::shared_ptr<EVP_PKEY> m_peer_pub_key;   // 对端 X25519 公钥
    std::vector<std::uint8_t> m_key_c2s;        // 客户端→服务端 会话密钥
    std::vector<std::uint8_t> m_key_s2c;        // 服务端→客户端 会话密钥
    std::vector<std::uint8_t> m_client_salt;    // 客户端随机盐（收到 KEY_RESP 后派生用）
    std::vector<std::uint8_t> m_server_salt;    // 服务端随机盐（服务端角色，KEY_EX 重传时复用）
    std::atomic<bool> m_enc_ready{ false };     // 密钥交换完成标志
    std::atomic<bool> m_is_client{ true };       // 本端是否发起方，决定加解密方向
private:
    static constexpr size_t VPN_MTU = 1400;
    static constexpr size_t KMax_packet_size = 1441;
};