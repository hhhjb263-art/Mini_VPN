#pragma once

#include <cstdint>
#include <cstddef>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <atomic>
#include <thread>
#include <string>
#include <memory>
#include <vector>
#include "../Buffer/tunnel_protoco.h"
#include "../Buffer/QueueBuffer.h"
#include "../Crypt/crypt.h"

/*
虚拟网卡 IP 数据包 → send_ip_packet → 封装隧道协议头 → 
推入 m_queue_send 发送队列 → send_thread 线程循环取出，通过 UDP socket 发给对端 VPN 客户端
*/
class UDP
{
private:
    static constexpr size_t VPN_MTU = 1400;
    static constexpr size_t KMax_packet_size = 1412;
private:
    int m_sock = -1;
    sockaddr_in clt_addr{};
    socklen_t clt_len {sizeof(clt_addr)};
    std::thread send_thread;
    std::thread recv_thread;
    std::thread heartbeat_thread;   // 心跳保活线程
    PacketQueue m_queue_send;
    PacketQueue m_queue_recv;

    uint32_t m_client_isn = 0;    // 客户端随机初始序列号（本机）
    uint32_t m_server_isn = 0;

    std::atomic <bool> m_running = false;
    std::atomic <bool> m_has_client = false;
    std::atomic <bool> m_handshaked = false;
    std::atomic <bool> m_need_connect = false;
    std::atomic<uint32_t> m_seq {0};
    std::atomic<uint64_t> m_last_heartbeat_ms{0};   // 最近收到对端心跳的时间(ms)
    mutable std::mutex m_client_mutex;

    // ===== 加密（X25519 + HKDF + AES-256-GCM）=====
    std::shared_ptr<EVP_PKEY> m_priv_key;      // 服务端 X25519 私钥
    std::vector<uint8_t> m_key_c2s;            // 客户端→服务端 会话密钥（服务端接收解密用）
    std::vector<uint8_t> m_key_s2c;            // 服务端→客户端 会话密钥（服务端发送加密用）
    std::vector<uint8_t> m_client_salt;        // 收到的客户端随机盐
    std::vector<uint8_t> m_server_salt;        // 服务端随机盐（KEY_EX 重传时复用）
    std::atomic<bool> m_enc_ready{false};      // 密钥交换完成标志
private:
    void send_work();
    void recv_work();

    bool send_handshake();
    bool handle_handshake(const tunnel_header &hdr,size_t len,const uint8_t *payload);
    bool handle_handshake_Re(const std::vector<uint8_t> &recv_handshake,const tunnel_header &hdr,size_t len);
    bool handle_heartbeat();
    void heartbeat_work();          // 周期发送心跳 + 对端超时检测
    bool start_threads();           // 启动 send/recv/heartbeat 线程
    void stop_threads();            // join 全部线程
    bool handle_key_exchange(const tunnel_header &hdr, size_t len, const uint8_t *payload);
public:
    UDP() = default;
    ~UDP();
    UDP(const UDP&) = delete;
    UDP &operator=(const UDP &) = delete; 
    UDP(UDP&& other) noexcept;
    UDP &operator=(UDP&& other) noexcept;

    bool is_running() const;
    bool is_handshaked() const;

    bool set_peer(const std::string &ip, uint16_t port);
    bool start(const std::string &local_ip, uint16_t local_port);      // 服务端：绑定并启动收发线程
    void stop();                                                       // 停止线程并关闭 socket
    void close();

    bool send_ip_packet(packet_buffer && buf);
    bool send_packet(uint8_t type,const uint8_t *data,size_t len,std::vector<uint8_t>& tmp_buf);
    bool recv_ip_packet(packet_buffer &buf);
    uint32_t GenerateISN();

    // 配置服务端 X25519 私钥（PEM）
    void set_credentials(std::shared_ptr<EVP_PKEY> priv_key);
    bool is_encrypted() const;
};