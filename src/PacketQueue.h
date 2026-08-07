#pragma once

#include "packet_buffer.h"

#include <queue>
#include <mutex>
#include <condition_variable>
#include <cstddef>
class PacketQueue
{
public:
	PacketQueue(size_t maxsize);
	~PacketQueue();
	bool push(packet_buffer&& buf);
	bool pop(packet_buffer& buf);
	bool try_pop(packet_buffer& buf); // 非阻塞弹出，无数据立即返回 false
	void shutdown();
	size_t size() const;
	bool empty() const;
private:
	size_t MaxSize;
	std::queue<packet_buffer> m_queue;
	mutable std::mutex m_mutex;
	std::condition_variable m_condition;
	bool m_shutdown{false};
};

