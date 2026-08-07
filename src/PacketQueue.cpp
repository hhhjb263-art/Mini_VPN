#include "PacketQueue.h"

PacketQueue::PacketQueue(size_t maxsize) : MaxSize(maxsize)
{

}

PacketQueue::~PacketQueue()
{
	shutdown();
}

bool PacketQueue::push(packet_buffer&& buf)
{
	{
		std::lock_guard<std::mutex> lock(m_mutex);
		if (m_shutdown) {
			return false;
		}
		if (m_queue.size() >= MaxSize) {
			return false;
		}
		m_queue.push(std::move(buf));
	}
	m_condition.notify_one();
	return true;
}

bool PacketQueue::pop(packet_buffer& buf)
{
	{
		std::unique_lock<std::mutex> lock(m_mutex);
		m_condition.wait(lock, [this] {
			return !m_queue.empty() || m_shutdown;
			});
		if (m_queue.empty()) {
			return false;
		}
		buf = std::move(m_queue.front());
		m_queue.pop();
	}
	return true;
}

bool PacketQueue::try_pop(packet_buffer& buf)
{
	std::lock_guard<std::mutex> lock(m_mutex);
	if (m_queue.empty()) {
		return false;
	}
	buf = std::move(m_queue.front());
	m_queue.pop();
	return true;
}

void PacketQueue::shutdown()
{
	{
		std::lock_guard<std::mutex> lock(m_mutex);
		m_shutdown = true;
	}
	m_condition.notify_all();
}
size_t PacketQueue::size() const {
	std::lock_guard<std::mutex> lock(m_mutex);
	return m_queue.size();
}
bool PacketQueue::empty() const {
	std::lock_guard<std::mutex> lock(m_mutex);
	return m_queue.empty();
}