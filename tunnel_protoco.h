#pragma once
#include <cstdint>
#include <winsock2.h>
#include <WS2tcpip.h>
#pragma comment(lib,"ws2_32.lib")

#pragma pack(push,1)
struct tunnel_header
{
    uint32_t magic;
    uint8_t version;
    uint8_t type;
    uint16_t payload_len;
    uint32_t sequence;
};
#pragma pack(pop)
enum version : uint8_t
{
    v_udp = 1,
    v_tcp = 2
};
enum type : uint8_t
{
    m_hand_request = 0,
    m_hand_response = 1,
    m_data = 2,
    m_heart = 3,
    m_heart_response = 4,
    disconnect = 5
};
enum HandshakeState {
    HS_IDLE,
    HS_SEND_REQ,    // 已发送握手请求，等待服务端ACK
    HS_WAIT_ACK,
    HS_SEND_FIN,    // 收到ACK，发送最终确认包
    HS_SUCCESS
};
constexpr uint32_t Kmagic = 0x4D56504E;
constexpr uint8_t Kversion = v_udp;
constexpr size_t Ktunnel_header = sizeof(tunnel_header);
constexpr size_t Max_payload_len = 1400;