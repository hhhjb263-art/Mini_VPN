#include "UDP.h"
#include "../Crypt/crypt.h"
#include <arpa/inet.h>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <system_error>
#include <openssl/rand.h>
#include <utility>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <iostream>
#include <random>
#include <chrono>
#include <thread>

// 数据包级日志开关：1=打印每个收发数据包（诊断用），0=只打关键事件
#ifndef VPN_PACKET_LOG
#define VPN_PACKET_LOG 1
#endif
/*
虚拟网卡 IP 数据包 → send_ip_packet → 封装隧道协议头 → 
推入 m_queue_send 发送队列 → send_thread 线程循环取出，通过 UDP socket 发给对端 VPN 服务 / 客户端
*/



// ===================== 握手负载（模仿 TCP 的 ISN/ACK 语义） =====================
// 三次握手（客户端视角）：
//   1) SYN     : type = m_hand_request , payload = { isn = 本端ISN,   ack = 0           }
//   2) SYN+ACK : type = m_hand_response, payload = { isn = 对端ISN,   ack = 本端ISN + 1 }
//   3) ACK     : type = m_hand_response, payload = { isn = 0,         ack = 对端ISN + 1 }
// 说明：
//   - ack 是确认号，指向对方 ISN 的下一个序号（等价于 TCP 的 ACK Number）；
//   - isn == 0 表示纯 ACK 包（不含 SYN 语义），用于区分 SYN+ACK 与 ACK；
//   - 握手期间 header.sequence 仅作参考，以负载中的 isn/ack 为准。
namespace{
    #pragma pack(push, 1)
    struct HandshakePayload {
        uint32_t isn; // 本端初始序列号；0 = 纯 ACK
        uint32_t ack; // 确认号：对端 ISN + 1
    };
    #pragma pack(pop)
    constexpr size_t kHandshakePayloadSize = sizeof(HandshakePayload);
    constexpr auto kHandshakeRetryInterval = std::chrono::milliseconds(500);
    constexpr auto kHandshakeTimeout = std::chrono::seconds(500);
    constexpr int kHandshakeMaxRetries = 10;

    // 心跳保活参数
    constexpr auto kHeartbeatInterval = std::chrono::seconds(10);   // 每 10s 发一次心跳
    constexpr auto kHeartbeatTimeout  = std::chrono::seconds(30);   // 30s 未收到对端响应判超时

    // 当前 steady_clock 毫秒时间戳
    uint64_t now_ms()
    {
        return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
    }

    // ===== 密钥交换辅助（X25519 + HKDF + AES-256-GCM）=====
    constexpr size_t kKeyExchangePayloadSize = 64; // 32B 公钥 + 32B 随机盐

    bool random_bytes(std::vector<uint8_t>& out)
    {
        return RAND_bytes(out.data(), static_cast<int>(out.size())) == 1;
    }

    bool get_raw_pubkey(EVP_PKEY* pkey, std::vector<uint8_t>& out)
    {
        if (pkey == nullptr)
            return false;
        size_t len = 0;
        if (EVP_PKEY_get_raw_public_key(pkey, nullptr, &len) != 1)
            return false;
        out.resize(len);
        return EVP_PKEY_get_raw_public_key(pkey, out.data(), &len) == 1;
    }

    EVP_PKEY* make_x25519_public_key(const uint8_t* raw, size_t len)
    {
        return EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, raw, len);
    }

    // 派生会话密钥：salt = client_salt || server_salt（客户端盐在前，顺序固定）
    bool derive_session_keys(
        EVP_PKEY* priv, EVP_PKEY* peer_pub,
        const std::vector<uint8_t>& client_salt,
        const std::vector<uint8_t>& server_salt,
        std::vector<uint8_t>& k_c2s,
        std::vector<uint8_t>& k_s2c)
    {
        std::vector<uint8_t> shared;
        try {
            shared = ecdh_derive_shared_secret(priv, peer_pub);
            std::vector<uint8_t> salt = client_salt;
            salt.insert(salt.end(), server_salt.begin(), server_salt.end());
            k_c2s = hkdf_derive_key(shared, salt, "c2s", AES256_KEY_LEN);
            k_s2c = hkdf_derive_key(shared, salt, "s2c", AES256_KEY_LEN);
            return true;
        } catch (...) {
            return false;
        }
    }
}

UDP::~UDP()
{
    close();
}

UDP::UDP(UDP&& other) noexcept
{
    std::scoped_lock lock(m_client_mutex, other.m_client_mutex);
    m_sock = std::exchange(other.m_sock, -1);

    // 客户端地址
    clt_addr = other.clt_addr;
    clt_len = other.clt_len;

    // 移动线程&队列
    send_thread = std::move(other.send_thread);
    recv_thread = std::move(other.recv_thread);
    heartbeat_thread = std::move(other.heartbeat_thread);
    m_queue_send = std::move(other.m_queue_send);
    m_queue_recv = std::move(other.m_queue_recv);

    m_running.store(other.m_running.load());
    m_has_client.store(other.m_has_client.load());
    m_handshaked.store(other.m_handshaked.load());
    m_need_connect.store(other.m_need_connect.load());
    m_seq.store(other.m_seq.load());
    m_last_heartbeat_ms.store(other.m_last_heartbeat_ms.load());
    // 清空源对象
    other.clt_addr = {};
    other.clt_len = 0;
    other.m_running.store(false);
    other.m_has_client.store(false);
    other.m_handshaked.store(false);
    other.m_need_connect.store(false);
    other.m_seq.store(0);
    other.m_last_heartbeat_ms.store(0);
}
UDP &UDP::operator=(UDP&& other) noexcept
{
    if(this != &other){
        std::scoped_lock lock(m_client_mutex, other.m_client_mutex);

        m_sock = other.m_sock;
        clt_addr = other.clt_addr;
        clt_len = other.clt_len;
        m_has_client.store(other.m_has_client.load());
        m_handshaked.store(other.m_handshaked.load());
        m_need_connect.store(other.m_need_connect.load());
        m_seq.store(other.m_seq.load());
        m_last_heartbeat_ms.store(other.m_last_heartbeat_ms.load());

        ::close(other.m_sock);
        other.m_sock = -1;
        other.m_has_client = false;
        other.clt_addr = {};
        other.clt_len = 0;
        other.m_handshaked.store(false);
        other.m_need_connect.store(false);
        other.m_seq.store(0);
        other.m_last_heartbeat_ms.store(0);
    }
    return *this;
}

void UDP::stop()
{
    if(!m_running.exchange(false)){
        // 未运行：仍回收可能残留的线程与 socket
        stop_threads();
        close();
        return;
    }
    // 先置位停止标志，再 shutdown 唤醒可能阻塞的系统调用
    if(m_sock >= 0){
        ::shutdown(m_sock, SHUT_RDWR);
    }
    stop_threads();
    close();
    // 清理会话密钥
    secure_wipe(m_key_c2s);
    secure_wipe(m_key_s2c);
    secure_wipe(m_client_salt);
    secure_wipe(m_server_salt);
    m_enc_ready.store(false);
}

void UDP::close()
{
    if(m_sock< 0){
        return;
    }
    ::shutdown(m_sock,SHUT_RDWR);
    ::close(m_sock);
    m_sock = -1;
}

bool UDP::is_running() const    
{
    return m_running.load() == true;
}

bool UDP::is_handshaked() const
{
    return m_handshaked.load() == true;
}

bool UDP::set_peer(const std::string &ip, uint16_t port)
{
    m_sock = socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
    if(m_sock < 0){
        fprintf(stderr, "[UDP] socket() failed: %s\n", strerror(errno));
        return false;
    }
    int reuse = 1;
    if(setsockopt(m_sock,SOL_SOCKET,SO_REUSEADDR,&reuse,sizeof(reuse)) < 0){
        fprintf(stderr, "[UDP] setsockopt(SO_REUSEADDR) failed: %s\n", strerror(errno));
    }
    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    
    if(ip.empty() || ip == "0.0.0.0"){
        server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    }else{
        int ret = inet_pton(AF_INET,ip.c_str(),&server_addr.sin_addr);
        if(ret != 1){
            fprintf(stderr, "[UDP] inet_pton(%s) failed: %s\n", ip.c_str(),
                    (ret == 0) ? "invalid address" : "unsupported family");
            close();
            return false;
        }
    }
    if(bind(m_sock,(struct sockaddr*)&server_addr,sizeof(server_addr)) < 0){
        fprintf(stderr, "[UDP] bind(%s:%u) failed: %s\n", ip.c_str(), port, strerror(errno));
        close();
        return false;
    }
    return true;
}

bool UDP::start(const std::string &local_ip, uint16_t local_port)
{
    if(is_running()){
        return true;   // 已在运行
    }
    // 服务端：绑定本地端口监听
    if(!set_peer(local_ip, local_port)){
        fprintf(stderr, "[UDP] start: set_peer(%s:%u) failed\n", local_ip.c_str(), local_port);
        return false;
    }
    // 非阻塞：让 recv_work 的 EAGAIN 分支生效，stop() 可快速退出
    int flags = fcntl(m_sock, F_GETFL, 0);
    if(flags != -1){
        fcntl(m_sock, F_SETFL, flags | O_NONBLOCK);
    }
    m_running.store(true);
    m_handshaked.store(false);
    m_need_connect.store(false);
    m_has_client.store(false);
    m_last_heartbeat_ms.store(0);
    if(!start_threads()){
        fprintf(stderr, "[UDP] start: start_threads failed\n");
        m_running.store(false);
        close();
        return false;
    }
    return true;
}

bool UDP::send_ip_packet(packet_buffer &&buf)
{
    if(!is_running()){
        return false;
    }
   return m_queue_send.push(std::move(buf));
}

bool UDP::send_packet(uint8_t type, const uint8_t *data, size_t len, std::vector<uint8_t> &tmp_buf)
{
    if(len > VPN_MTU)
        return false;
    size_t total_len = Ktunnel_header + len;
    tmp_buf.resize(total_len);
    tunnel_header hdr{};
    memset(&hdr,0,sizeof(hdr));
    hdr.magic = Kmagic;
    hdr.version = Kversion;
    hdr.type = type;
    hdr.payload_len = htons(static_cast<uint16_t>(len));
    uint32_t seq = m_seq.fetch_add(1);
    hdr.sequence = htonl(seq);
    memcpy(tmp_buf.data(),&hdr,Ktunnel_header);
    // 数据面加密：m_data / m_heart / m_heart_response 在密钥就绪后以密文发送（服务端用 k_s2c）
    if(m_enc_ready.load() &&
        (type == static_cast<uint8_t>(m_data) ||
         type == static_cast<uint8_t>(m_heart) ||
         type == static_cast<uint8_t>(m_heart_response))){
        // inner = [type][data]；AAD = 外层头（前 Ktunnel_header 字节）
        std::vector<uint8_t> inner;
        inner.reserve(1 + len);
        inner.push_back(type);
        if(len)
            inner.insert(inner.end(), data, data + len);
        // AAD = the header actually sent: set payload_len to ciphertext length BEFORE encrypting
        hdr.payload_len = htons(static_cast<uint16_t>(len + 1 + AES_GCM_NONCE_LEN + AES_GCM_TAG_LEN));
        memcpy(tmp_buf.data(),&hdr,Ktunnel_header);
        std::vector<uint8_t> enc;
        try {
            enc = aes256_gcm_encrypt(m_key_s2c, inner.data(), inner.size(),
                                     tmp_buf.data(), Ktunnel_header);
        } catch(const std::exception &e){
            fprintf(stderr, "[UDP] 加密失败: %s\n", e.what());
            return false;
        }
        if(Ktunnel_header + enc.size() > KMax_packet_size){
            fprintf(stderr, "[UDP] 加密后包过大: %zu\n", enc.size());
            return false;
        }
        // 更新 payload_len 为密文长度

        tmp_buf.resize(Ktunnel_header + enc.size());
        memcpy(tmp_buf.data() + Ktunnel_header, enc.data(), enc.size());
        total_len = Ktunnel_header + enc.size();
    } else {
        if(len)
            memcpy(tmp_buf.data() + Ktunnel_header,data,len);
    }
    int ret = sendto(m_sock,tmp_buf.data(),total_len,0,(struct sockaddr*)&clt_addr,(socklen_t)clt_len);
    if(ret == -1){
        fprintf(stderr, "[UDP] sendto() failed: %s\n", strerror(errno));
        m_need_connect.store(true);
        return false;
    }
    if(static_cast<size_t>(ret) != total_len){
        fprintf(stderr, "[UDP] sendto() partial send: %d / %zu bytes\n", ret, total_len);
        m_need_connect.store(true);
        return false;
    }
    return true;
}

bool UDP::recv_ip_packet(packet_buffer &buf)
{
    if(!is_running()){
        return false;
    }
    return m_queue_recv.pop(buf);
}
void UDP::send_work()
{
    std::vector<uint8_t> sendbuf;
    sendbuf.reserve(KMax_packet_size);
    packet_buffer buf;

    while(is_running()){
        if(!is_handshaked()){
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }
        if(!m_queue_send.pop(buf)){
            // 队列空：短暂休眠再取，避免忙轮询，线程保持运行
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            continue;
        }
        if(buf.is_empty()){
            continue;
        }
        size_t pay_size = buf.data_size();
        if(pay_size > Max_payload_len){
            buf.clear();
            continue;
        }
#if VPN_PACKET_LOG
        fprintf(stderr, "[UDP][TX] 发送数据 len=%zu\n", pay_size);
#endif
        if(!send_packet(m_data,buf.get_data(),pay_size,sendbuf)){
            m_need_connect.store(true);
            break;
        }
        buf.clear();
    }
}

void UDP::recv_work()
{
    std::vector<uint8_t> recvbuf;
    std::vector<uint8_t> sendbuf;
    sendbuf.reserve(KMax_packet_size);
    recvbuf.reserve(KMax_packet_size + 64);
    sockaddr_in peer_addr{};

    while(is_running()){
        recvbuf.resize(KMax_packet_size);
        socklen_t peer_addr_size = sizeof(peer_addr);

        int ret = recvfrom(m_sock, recvbuf.data(), recvbuf.size(), 0,
                           (struct sockaddr*)&peer_addr, &peer_addr_size);
        if(ret <= 0){
            if(errno == EAGAIN || errno == EWOULDBLOCK){
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
                continue;   // 非阻塞下无数据，短暂休眠后重试
            }
            fprintf(stderr, "[UDP] recvfrom() failed: %s\n", strerror(errno));
            m_need_connect.store(true);
            break;
        }
        if(ret < static_cast<int>(Ktunnel_header)){
            fprintf(stderr, "[UDP] packet too short: %d < %zu bytes\n", ret, Ktunnel_header);
            continue;   // 包太短
        }

        // 解析隧道头
        tunnel_header hdr{};
        memcpy(&hdr, recvbuf.data(), Ktunnel_header);
        if(hdr.magic != Kmagic || hdr.version != Kversion){
            fprintf(stderr, "[UDP] bad header: magic=%#x version=%u (expected magic=%#x version=%u)\n",
                    hdr.magic, hdr.version, Kmagic, Kversion);
            continue;
        }

        size_t pay_len = ntohs(hdr.payload_len);
        if(pay_len > Max_payload_len || pay_len + Ktunnel_header > static_cast<size_t>(ret)){
            fprintf(stderr, "[UDP] invalid payload_len=%zu (received %d bytes)\n", pay_len, ret);
            continue;
        }
        // 记录对端地址: 后续 sendto 需要用它作为目标
        clt_addr = peer_addr;
        clt_len = peer_addr_size;
#if VPN_PACKET_LOG
        {
            char ipstr[INET_ADDRSTRLEN] = {0};
            inet_ntop(AF_INET, &peer_addr.sin_addr, ipstr, sizeof(ipstr));
            fprintf(stderr, "[UDP][RX] type=%d len=%zu from=%s:%u\n",
                    hdr.type, pay_len, ipstr, ntohs(peer_addr.sin_port));
        }
#endif

        // ===== 加密类型：密钥就绪后 m_data / m_heart / m_heart_response 均为密文 =====
        if(hdr.type == static_cast<uint8_t>(m_data) ||
           hdr.type == static_cast<uint8_t>(m_heart) ||
           hdr.type == static_cast<uint8_t>(m_heart_response)){
            if(!m_enc_ready.load()){
                fprintf(stderr, "[UDP] 密钥未就绪，丢弃加密数据 type=%d len=%zu\n", hdr.type, pay_len);
                continue;
            }
            std::vector<uint8_t> enc(recvbuf.data() + Ktunnel_header,
                                     recvbuf.data() + Ktunnel_header + pay_len);
            std::optional<std::vector<uint8_t>> plain;
            try {
                plain = aes256_gcm_decrypt(m_key_c2s, enc, recvbuf.data(), Ktunnel_header);
            } catch(const std::exception &e){
                fprintf(stderr, "[UDP] 解密异常: %s\n", e.what());
                continue;
            }
            if(!plain){
                fprintf(stderr, "[UDP] 解密认证失败，丢弃\n");
                continue;
            }
            uint8_t inner_type = 0;
            std::vector<uint8_t> inner_payload;
            if(!parse_inner_packet(*plain, inner_type, inner_payload)){
                continue;
            }
            switch(inner_type){
            case m_data:
                if(inner_payload.empty())
                    break;
                m_last_heartbeat_ms.store(now_ms());   // 数据包也算对端存活
#if VPN_PACKET_LOG
                fprintf(stderr, "[UDP][RX] 数据包入队 len=%zu\n", inner_payload.size());
#endif
                m_queue_recv.push(packet_buffer(std::move(inner_payload)));
                break;
            case m_heart:
                m_last_heartbeat_ms.store(now_ms());
                fprintf(stderr, "[UDP] 收到心跳\n");
                send_packet(static_cast<uint8_t>(m_heart_response), nullptr, 0, sendbuf);
                break;
            case m_heart_response:
                m_last_heartbeat_ms.store(now_ms());
                fprintf(stderr, "[UDP] 收到心跳确认\n");
                break;
            default:
                break;
            }
            continue;
        }

        // ===== 明文类型：握手 / 密钥交换 / 断开 =====
        switch(hdr.type)
        {
        case m_hand_request:
            fprintf(stderr, "[UDP][HS] 收到握手请求(SYN)\n");
            handle_handshake(hdr,pay_len,(recvbuf.data() + Ktunnel_header));
            break; 
        case m_hand_response:
            handle_handshake_Re(recvbuf,hdr,pay_len);
            break;
        case m_data:
            {
                if(!is_handshaked()){
                    break;
                }
                m_last_heartbeat_ms.store(now_ms());   // 数据包也算对端存活
#if VPN_PACKET_LOG
                fprintf(stderr, "[UDP][RX] 数据包入队 len=%zu\n", pay_len);
#endif
                // 将 IP 数据包推入接收队列
                std::vector<uint8_t> tmp_buf(recvbuf.data() + Ktunnel_header ,recvbuf.data() + Ktunnel_header + pay_len);
                packet_buffer buf(std::move(tmp_buf));
                m_queue_recv.push(std::move(buf));
                break;
            }
        case m_heart:
            m_last_heartbeat_ms.store(now_ms());   // 收到对端心跳 → 存活
            fprintf(stderr, "[UDP] 收到心跳\n");
            handle_heartbeat();
            break;
        case m_heart_response:
            m_last_heartbeat_ms.store(now_ms());   // 心跳确认 → 更新存活时间
            fprintf(stderr, "[UDP] 收到心跳确认\n");
            break;
        case m_key_exchange:
            handle_key_exchange(hdr,pay_len,(recvbuf.data() + Ktunnel_header));
            break;
        case m_key_response:
            // 服务端角色不应收到 KEY_RESP，忽略
            break;
        case disconnect:
            m_need_connect.store(true);
            m_handshaked.store(false);
            fprintf(stderr, "[UDP] 收到断开消息\n");
            break;
        default:
            break;
        }
    }
}

bool UDP::handle_handshake(const tunnel_header &hdr,size_t len,const uint8_t *payload)
{
    (void)hdr;
    std::vector<uint8_t> send_handshake;
    if(len < kHandshakePayloadSize){
        fprintf(stderr, "[UDP][HS] handshake payload too short: %zu < %zu bytes\n",
                len, kHandshakePayloadSize);
        return false;
    }
    HandshakePayload syn{};
    memcpy(&syn,payload,kHandshakePayloadSize);

    if(syn.isn == 0){
        fprintf(stderr, "[UDP][HS] received SYN with isn==0\n");
        return false;
    }
    
    // 收到对端 SYN：保存对端 ISN，回复 SYN+ACK {本机ISN, 对端ISN+1}
    // 首次应答前生成自己的 ISN (等价于主动方发送 SYN 前的初始化)
    if(m_client_isn == 0){
        m_client_isn = GenerateISN();
    }
    m_server_isn = syn.isn;
    HandshakePayload synack{m_client_isn , m_server_isn + 1};
    if(!send_packet(static_cast<uint8_t>(m_hand_response),reinterpret_cast<const uint8_t*>(&synack),kHandshakePayloadSize,send_handshake)){
        fprintf(stderr, "[UDP][HS] send SYN+ACK failed\n");
        return false;
    }
    fprintf(stderr, "[UDP][HS] 已回复 SYN+ACK (server_isn=%u)\n", m_client_isn);
    return true;
}

bool UDP::handle_handshake_Re(const std::vector<uint8_t> &recv_handshake,const tunnel_header &hdr,size_t len)
{
    (void)hdr;
    if(len < kHandshakePayloadSize){
        fprintf(stderr, "[UDP][HS] handshake response too short: %zu < %zu bytes\n",
                len, kHandshakePayloadSize);
        return false;
    }

    HandshakePayload hs{};
    memcpy(&hs,recv_handshake.data() + Ktunnel_header,kHandshakePayloadSize);

    if(hs.isn != 0){
        // ===== 本机是发起方，收到对端的 SYN+ACK =====
        if(hs.ack != m_client_isn + 1){
            fprintf(stderr, "[UDP][HS] SYN+ACK ack mismatch: got %u, expect %u\n",
                    hs.ack, m_client_isn + 1);
            return false;
        }
        m_server_isn = hs.isn;
        fprintf(stderr, "[UDP][HS] 收到 SYN+ACK (server_isn=%u)，发送最终 ACK\n", m_server_isn);
        // 发送最终 ACK：{isn=0, ack=对端ISN+1}
        HandshakePayload ack{0, m_server_isn + 1};
        std::vector<uint8_t> sendbuf;
        if(!send_packet(static_cast<uint8_t>(m_hand_response),
                        reinterpret_cast<const uint8_t*>(&ack), kHandshakePayloadSize, sendbuf)){
            fprintf(stderr, "[UDP][HS] send final ACK failed\n");
            return false;
        }
        m_handshaked.store(true);
        return true;
    } else {
        // ===== 本机是响应方，收到对端的最终 ACK =====
        if(hs.ack != m_client_isn + 1){
            fprintf(stderr, "[UDP][HS] final ACK ack mismatch: got %u, expect %u\n",
                    hs.ack, m_client_isn + 1);
            return false;
        }
        m_handshaked.store(true);
        fprintf(stderr, "[UDP][HS] 握手完成 (server_isn=%u)\n", m_server_isn);
        return true;
    }
}


bool UDP::handle_heartbeat()
{
    std::vector<uint8_t> sendbuf;
    return send_packet(m_heart_response, nullptr, 0, sendbuf);
}

void UDP::set_credentials(std::shared_ptr<EVP_PKEY> priv_key)
{
    m_priv_key = std::move(priv_key);
}

bool UDP::is_encrypted() const
{
    return m_enc_ready.load();
}

bool UDP::handle_key_exchange(const tunnel_header &hdr, size_t len, const uint8_t *payload)
{
    (void)hdr;
    if(len != kKeyExchangePayloadSize){
        fprintf(stderr, "[UDP][KEY] KEY_EX 长度错误: %zu != %zu\n", len, kKeyExchangePayloadSize);
        return false;
    }
    if(!m_priv_key){
        fprintf(stderr, "[UDP][KEY] 未配置服务端 X25519 私钥\n");
        return false;
    }
    // 首次收到才生成服务端盐；KEY_EX 重传时复用同一盐，避免两端密钥错位
    if(m_server_salt.empty()){
        m_server_salt.resize(32);
        if(!random_bytes(m_server_salt)){
            fprintf(stderr, "[UDP][KEY] 生成服务端盐失败\n");
            return false;
        }
    }
    std::vector<uint8_t> my_pub;
    if(!get_raw_pubkey(m_priv_key.get(), my_pub)){
        fprintf(stderr, "[UDP][KEY] 取服务端公钥失败\n");
        return false;
    }
    // 回复 KEY_RESP：服务端公钥(32) + 服务端盐(32)
    std::vector<uint8_t> resp;
    resp.reserve(kKeyExchangePayloadSize);
    resp.insert(resp.end(), my_pub.begin(), my_pub.end());
    resp.insert(resp.end(), m_server_salt.begin(), m_server_salt.end());
    std::vector<uint8_t> sendbuf;
    if(!send_packet(static_cast<uint8_t>(m_key_response), resp.data(), resp.size(), sendbuf)){
        fprintf(stderr, "[UDP][KEY] 发送 KEY_RESP 失败\n");
        return false;
    }
    fprintf(stderr, "[UDP][KEY] 已回复 KEY_RESP\n");
    // 派生会话密钥（首次）
    if(!m_enc_ready.load()){
        std::vector<uint8_t> peer_pub(payload, payload + 32);
        std::vector<uint8_t> peer_salt(payload + 32, payload + kKeyExchangePayloadSize);
        EVP_PKEY *peer = make_x25519_public_key(peer_pub.data(), peer_pub.size());
        if(peer != nullptr){
            // 服务端角色：client_salt = 收到的客户端盐，server_salt = 自己的盐
            if(derive_session_keys(m_priv_key.get(), peer, peer_salt, m_server_salt, m_key_c2s, m_key_s2c)){
                m_enc_ready.store(true);
                fprintf(stderr, "[UDP][KEY] 密钥交换完成，隧道已加密\n");
            } else {
                fprintf(stderr, "[UDP][KEY] 派生会话密钥失败\n");
            }
            EVP_PKEY_free(peer);
        } else {
            fprintf(stderr, "[UDP][KEY] 构造客户端公钥失败\n");
        }
    }
    return true;
}

bool UDP::start_threads()
{
    try{
        send_thread = std::thread(&UDP::send_work, this);
        recv_thread = std::thread(&UDP::recv_work, this);
        heartbeat_thread = std::thread(&UDP::heartbeat_work, this);
    }catch(const std::system_error &e){
        fprintf(stderr, "[UDP] start_threads failed: %s\n", e.what());
        stop_threads();
        return false;
    }
    return true;
}

void UDP::stop_threads()
{
    if(send_thread.joinable()){
        send_thread.join();
    }
    if(recv_thread.joinable()){
        recv_thread.join();
    }
    if(heartbeat_thread.joinable()){
        heartbeat_thread.join();
    }
}

void UDP::heartbeat_work()
{
    while(is_running()){
        std::this_thread::sleep_for(kHeartbeatInterval);
        if(!is_running()){
            break;
        }
        if(!is_handshaked()){
            continue;   // 尚未握手，无需保活
        }
        // 超时检测：超过 kHeartbeatTimeout 未收到对端任何包 → 判定失联
        uint64_t last = m_last_heartbeat_ms.load();
        uint64_t timeout_ms = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(kHeartbeatTimeout).count());
        if(last != 0 && (now_ms() - last) > timeout_ms){
            fprintf(stderr, "[UDP] heartbeat timeout, peer considered dead\n");
            m_handshaked.store(false);
            m_need_connect.store(true);
            continue;
        }
        // 主动发送心跳
        std::vector<uint8_t> sendbuf;
        fprintf(stderr, "[UDP] 发送心跳\n");
        if(!send_packet(m_heart, nullptr, 0, sendbuf)){
            fprintf(stderr, "[UDP] send heartbeat failed\n");
            m_need_connect.store(true);
        }
    }
}

bool UDP::send_handshake()
{
    if(m_sock < 0){
        fprintf(stderr, "[UDP][HS] send_handshake: socket not created\n");
        return false;
    }
    if(m_client_isn == 0){
        m_client_isn = GenerateISN();
    }
    // 发送 SYN：{本机ISN, ack=0}
    HandshakePayload syn{m_client_isn, 0};
    std::vector<uint8_t> sendbuf;
    if(!send_packet(static_cast<uint8_t>(m_hand_request),
                    reinterpret_cast<const uint8_t*>(&syn), kHandshakePayloadSize, sendbuf)){
        fprintf(stderr, "[UDP][HS] send SYN failed\n");
        return false;
    }
    return true;
}

uint32_t UDP::GenerateISN()
{
	static std::random_device rd;
	static std::mt19937 generator(rd());
	static std::uniform_int_distribution<uint32_t> dist;
	return dist(generator);
}