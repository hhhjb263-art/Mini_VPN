#include "UDP.h"
#include <cstdio>
#include <chrono>
#include <cstring>
#include <random>

namespace {

// ===================== 握手负载（模仿 TCP 的 ISN/ACK 语义） =====================
// 三次握手（客户端视角）：
//   1) SYN     : type = m_hand_request , payload = { isn = 本端ISN,   ack = 0           }
//   2) SYN+ACK : type = m_hand_response, payload = { isn = 对端ISN,   ack = 本端ISN + 1 }
//   3) ACK     : type = m_hand_response, payload = { isn = 0,         ack = 对端ISN + 1 }
// 说明：
//   - ack 是确认号，指向对方 ISN 的下一个序号（等价于 TCP 的 ACK Number）；
//   - isn == 0 表示纯 ACK 包（不含 SYN 语义），用于区分 SYN+ACK 与 ACK；
//   - 握手期间 header.sequence 仅作参考，以负载中的 isn/ack 为准。
#pragma pack(push, 1)
struct HandshakePayload {
    uint32_t isn; // 本端初始序列号；0 = 纯 ACK
    uint32_t ack; // 确认号：对端 ISN + 1
};
#pragma pack(pop)
constexpr size_t kHandshakePayloadSize = sizeof(HandshakePayload);

constexpr auto kHandshakeRetryInterval = std::chrono::milliseconds(500); // SYN 重传间隔（简化 RTO）
constexpr int kHandshakeMaxRetries = 10;                                 // 最大重传次数
constexpr auto kHandshakeTimeout = std::chrono::seconds(5);              // 握手总超时
	constexpr auto kHeartbeatTimeout = std::chrono::seconds(5);	// 心跳超时：超过该时长未收到对端任何报文即判定断线

}

UDP::UDP(const char* remoteip, uint16_t port, bool is_running, size_t queueMax) :
	m_sock(INVALID_SOCKET), m_sendqueue(queueMax), m_recvqueue(queueMax)
{
	memset(&m_sockaddr, 0, sizeof(m_sockaddr));
	m_sockaddr.sin_family = AF_INET;
	m_sockaddr.sin_port = htons(port);
	int ret = inet_pton(AF_INET, remoteip, &m_sockaddr.sin_addr);
	if (ret != 1) {
		throw std::invalid_argument("invalid remote ip address");
	}
}

UDP::~UDP()
{
	stop();
	if (m_sock != INVALID_SOCKET) {
		closesocket(m_sock);
		m_sock = INVALID_SOCKET;
	}
	WSACleanup();
}

bool UDP::init()
{
	if (m_running.load() || send_thread.joinable() || recv_thread.joinable()) {
		return false; // 已经初始化过了, 避免重复创建线程/泄漏 socket
	}
	WSADATA wsa;
	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
		return false;
	}
	m_sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (m_sock == INVALID_SOCKET) {
		WSACleanup();
		return false;
	}
	// 握手准备：生成客户端 ISN（TCP 的初始序列号），在启动线程前设置，避免跨线程数据竞争
	m_client_isn = GenerateISN();
	m_server_isn = 0;
	m_hs_state = HS_IDLE;
	m_handshaked.store(false);
	m_need_reconnect.store(false);
	m_seq.store(0, std::memory_order_relaxed);
		m_last_rx_ms.store(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count());

	m_running = true;
	send_thread = std::thread(&UDP::send_work, this);
	recv_thread = std::thread(&UDP::recv_work, this);
	return true;
}

void UDP::stop()
{
	m_running = false;
	m_sendqueue.shutdown();
	m_recvqueue.shutdown();
	// 先关闭 socket，让阻塞在 recvfrom 上的接收线程立即返回，再回收线程，避免 stop 卡死
	if (m_sock != INVALID_SOCKET) {
		closesocket(m_sock);
		m_sock = INVALID_SOCKET;
	}
	if (send_thread.joinable())
		send_thread.join();
	if (recv_thread.joinable())
		recv_thread.join();
	m_handshaked.store(false);
	m_need_reconnect.store(false);
	m_hs_state = HS_IDLE;
	m_client_isn = 0;
	m_server_isn = 0;
		m_last_rx_ms.store(0);
}

// 网卡将数据填入队列
void UDP::send_ip_packet(packet_buffer&& buf)
{
	if (!m_running.load()) {
		return;
	}
	m_sendqueue.push(std::move(buf));
}

bool UDP::recv_ip_packet(packet_buffer& buf)
{
	if (!m_running.load()) {
		return false;
	}
	return m_recvqueue.pop(buf);
}

bool UDP::try_recv_ip_packet(packet_buffer& buf)
{
	if (!m_running.load()) {
		return false;
	}
	return m_recvqueue.try_pop(buf);
}

bool UDP::send_packet(uint8_t type, const uint8_t* data, size_t len, std::vector<uint8_t>& sendbuf)
{
	if (len > VPN_MTU)
		return false;
	size_t total_len = Ktunnel_header + len;
	sendbuf.resize(total_len);
	tunnel_header header{};

	header.magic = Kmagic;
	header.version = static_cast<uint8_t>(Kversion);
	header.type = type;
	header.payload_len = htons(static_cast<uint16_t>(len));
	uint32_t seq = m_seq.fetch_add(1);
	header.sequence = htonl(seq);

	memcpy(sendbuf.data(), &header, Ktunnel_header);
	if (len) {
		memcpy(sendbuf.data() + Ktunnel_header, data, len);
	}
	int ret = sendto(m_sock, reinterpret_cast<const char*>(sendbuf.data()), static_cast<int>(total_len), 0,
		reinterpret_cast<const sockaddr*>(&m_sockaddr), sizeof(m_sockaddr));
	if (ret == SOCKET_ERROR)
	{
		int err = WSAGetLastError();
		// 对端端口不可达，标记隧道需要重连
		if (err == WSAECONNRESET)
		{
			m_need_reconnect.store(true);
		}
		return false;
	}
	return true;
}

void UDP::send_work()
{
	std::vector<uint8_t> sendbuf;
	sendbuf.reserve(KMax_packet_size);
	packet_buffer buf;

	using clock_type = std::chrono::steady_clock;
	auto handshake_start = clock_type::now();
	auto last_syn = handshake_start;
	auto last_heart = handshake_start;
	int syn_retries = 0;

	// ============ 三次握手（模仿 TCP）：SYN -> SYN+ACK -> ACK ============
	// 客户端先发 SYN，携带本端 ISN
	m_seq.store(m_client_isn, std::memory_order_relaxed);
	{
		HandshakePayload syn{ m_client_isn, 0 };
		send_packet(static_cast<uint8_t>(m_hand_request),
			reinterpret_cast<const uint8_t*>(&syn), kHandshakePayloadSize, sendbuf);
	}
	m_hs_state = HS_SEND_REQ;

	while (m_running.load() && !m_handshaked.load())
	{
		auto now = clock_type::now();

		// 握手总超时：超时视为对端不可达
		if (now - handshake_start > kHandshakeTimeout) {
			m_need_reconnect.store(true);
			break;
		}
		if (m_need_reconnect.load()) {
			break;
		}

		// SYN 超时重传（TCP 的 RTO 重传，这里简化为固定间隔）
		if (now - last_syn >= kHandshakeRetryInterval) {
			if (++syn_retries > kHandshakeMaxRetries) {
				m_need_reconnect.store(true);
				break;
			}
			// 重传的 SYN 保持同一序号（TCP 语义）
			m_seq.store(m_client_isn, std::memory_order_relaxed);
			HandshakePayload syn{ m_client_isn, 0 };
			send_packet(static_cast<uint8_t>(m_hand_request),
				reinterpret_cast<const uint8_t*>(&syn), kHandshakePayloadSize, sendbuf);
			m_hs_state = HS_SEND_REQ;
			last_syn = now;
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(20));
	}

	if (!m_handshaked.load()) {
		// 握手失败（超时 / 对端不可达），交由上层决定重连
		m_hs_state = HS_IDLE;
		return;
	}

	// 握手成功：进入 ESTABLISHED
	m_hs_state = HS_SUCCESS;
	// 序号由 send_packet 的 fetch_add 原子递增（握手 ACK 已消耗 ISN+1，无需重置）

	// ============ 已建立连接：心跳保活 + 数据转发 ============
	while (m_running.load())
	{
		if (m_need_reconnect.load()) {
			break;
		}
		auto now = clock_type::now();

		// 心跳（TCP keepalive 的简化版）
		if (now - last_heart >= std::chrono::seconds(1)) {
			send_packet(static_cast<uint8_t>(m_heart), nullptr, 0, sendbuf);
			last_heart = now;
		}
		// 心跳超时：超过 kHeartbeatTimeout 未收到对端任何报文 -> 判定链路失效
		if (m_last_rx_ms.load() != 0 &&
			now - std::chrono::steady_clock::time_point(std::chrono::milliseconds(m_last_rx_ms.load())) > kHeartbeatTimeout) {
			fprintf(stderr, "[UDP] heartbeat timeout, peer unreachable, reconnecting\n");
			m_need_reconnect.store(true);
			break;
		}

		// 队列为空时短暂休眠，避免阻塞导致心跳无法周期发送
		if (m_sendqueue.empty()) {
			std::this_thread::sleep_for(std::chrono::milliseconds(20));
			continue;
		}
		if (!m_sendqueue.pop(buf)) {
			break;
		}
		if (buf.is_empty()) {
			continue;
		}
		size_t paysize = buf.data_size();
		if (paysize > VPN_MTU) {
			buf.clear();
			continue;
		}
		if (!send_packet(static_cast<uint8_t>(m_data), buf.get_data(), paysize, sendbuf)) {
			m_need_reconnect.store(true);
			break;
		}
		buf.clear();
	}

	// ============ 主动断开（模仿 TCP FIN，尽力发送，不阻塞等待对端确认） ============
	if (m_handshaked.load() && !m_need_reconnect.load()) {
		m_hs_state = HS_SEND_FIN;
		send_packet(static_cast<uint8_t>(disconnect), nullptr, 0, sendbuf);
		m_hs_state = HS_IDLE;
	}
}

/*
	struct tunnel_header
{
	uint32_t magic;			    4
	uint8_t version;		    1
	uint8_t type;			    1
	uint16_t payload_len;		2
	uint32_t sequence;			4
};  12
*/
void UDP::recv_work()
{
	std::vector<uint8_t> recv_buf;
	std::vector<uint8_t> sendbuf;
	packet_buffer buf;
	recv_buf.reserve(KMax_packet_size);
	sendbuf.reserve(KMax_packet_size);
	while (m_running.load())
	{
		recv_buf.resize(KMax_packet_size);
		sockaddr_in peer_addr{};
		int peer_len = static_cast<int>(sizeof(peer_addr));
		int ret = recvfrom(
			m_sock,
			reinterpret_cast<char*>(recv_buf.data()),
			static_cast<int>(recv_buf.size()),
			0,
			reinterpret_cast<sockaddr*>(&peer_addr),
			&peer_len
		);
		if (ret <= 0) {
			continue;
		}
		if (static_cast<size_t>(ret) < Ktunnel_header) {
			continue;
		}
		tunnel_header header{};
		memcpy(&header, recv_buf.data(), Ktunnel_header);
		if (header.magic != Kmagic) {
			continue;
		}
		if (header.version != static_cast<uint8_t>(Kversion)) {
			continue;
		}
		size_t payload_len = ntohs(header.payload_len);
		if (payload_len > Max_payload_len) {
			continue;
		}
		// 校验报文完整性：头部 + payload 长度不超过实际收到字节数
		if (static_cast<size_t>(ret) < Ktunnel_header + payload_len) {
			continue;
		}
		// 任何合法报文都视为对端存活
		m_last_rx_ms.store(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count());
		const uint8_t* payload = recv_buf.data() + Ktunnel_header;

		switch (header.type)
		{
		case m_hand_request:
		{
			// 收到对端 SYN（本端充当服务端的场景）：回复 SYN+ACK
			if (payload_len < kHandshakePayloadSize) {
				break;
			}
			HandshakePayload syn{};
			memcpy(&syn, payload, kHandshakePayloadSize);
			if (syn.isn == 0) {
				break; // 非法 SYN
			}
			m_server_isn = syn.isn;
			HandshakePayload synack{ m_client_isn, m_server_isn + 1 };
			send_packet(static_cast<uint8_t>(m_hand_response),
				reinterpret_cast<const uint8_t*>(&synack), kHandshakePayloadSize, sendbuf);
			break;
		}
		case m_hand_response:
		{
			// 收到 SYN+ACK / ACK
			if (payload_len < kHandshakePayloadSize) {
				break;
			}
			HandshakePayload hs{};
			memcpy(&hs, payload, kHandshakePayloadSize);
			// 确认号必须指向我方 ISN 的下一个序号，否则丢弃（TCP 语义）
			if (hs.ack != m_client_isn + 1) {
				break;
			}
			if (hs.isn != 0) {
				// SYN+ACK：记录对端 ISN，并回复 ACK，完成第三次握手
				m_server_isn = hs.isn;
				HandshakePayload ack{ 0, m_server_isn + 1 };
				send_packet(static_cast<uint8_t>(m_hand_response),
					reinterpret_cast<const uint8_t*>(&ack), kHandshakePayloadSize, sendbuf);
				m_handshaked.store(true); // ESTABLISHED
				// 若对端重传 SYN+ACK，这里会重复回复 ACK（幂等，可容忍丢包）
			}
			else if (m_server_isn != 0) {
				// 纯 ACK：对端确认了我们的 SYN+ACK（本端充当服务端时连接建立）
				m_handshaked.store(true);
			}
			break;
		}
		case m_data:
		{
			if (payload_len == 0) {
				break;
			}
			// packet_buffer 构造时深拷贝数据，recv_buf 可安全复用
			packet_buffer pbuf(const_cast<uint8_t*>(payload), payload_len);
			m_recvqueue.push(std::move(pbuf));
			break;
		}
		case m_heart:
			// 对端心跳：回复心跳响应
			send_packet(static_cast<uint8_t>(m_heart_response), nullptr, 0, sendbuf);
			break;
		case m_heart_response:
			// 心跳确认：可用于链路检测，暂不处理
			send_packet(static_cast<uint8_t> (m_heart_response), nullptr, 0, sendbuf);
			break;
		case disconnect:
			// 对端 FIN：回复 FIN（近似 FIN+ACK），并标记需要重连
			send_packet(static_cast<uint8_t>(disconnect), nullptr, 0, sendbuf);
			m_need_reconnect.store(true);
			break;
		default:
			break;
		}
	}
}

uint32_t UDP::GenerateISN()
{
	static std::random_device rd;
	static std::mt19937 generator(rd());
	static std::uniform_int_distribution<uint32_t> dist;
	return dist(generator);
}