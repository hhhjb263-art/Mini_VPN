#include "QueueBuffer.h"

PacketQueue::PacketQueue(size_t max_size)
    : Max_size(max_size)
{
}

void PacketQueue::set_max_size(size_t n)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    Max_size = n;
}

PacketQueue::PacketQueue(PacketQueue&& other) noexcept
    : Max_size(std::exchange(other.Max_size, 0))
    , m_queue(std::move(other.m_queue))
    , m_shutdown(other.m_shutdown)
{
    other.m_shutdown = false;
}

PacketQueue &PacketQueue::operator=(PacketQueue&& other) noexcept
{
    if (this != &other)
    {
        shutdown();
        Max_size = std::exchange(other.Max_size, 0);
        m_queue = std::move(other.m_queue);
        m_shutdown = other.m_shutdown;
        other.m_shutdown = false;
    }
    return *this;
}

PacketQueue::~PacketQueue()
{
    shutdown();
}

void PacketQueue::shutdown()
{
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_shutdown = true;
    }
    m_condition.notify_all();
}
// 服务器 ->  tun ->  push（） ->  隧道  
bool PacketQueue::push(packet_buffer &&buf)
{
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if(m_shutdown){
            return false;
        }
        if(m_queue.size() > Max_size)
            return false;
        m_queue.push(std::move(buf));
    }
    m_condition.notify_one();
    return true;
}

bool PacketQueue::pop(packet_buffer &buf)
{
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if(m_shutdown){
            return false;
        }
        // 直接检查队列，不要调用 is_empty()（它内部会再次加锁，嵌套锁导致死锁）
        if(m_queue.empty()){
            return false;
        }
        buf = std::move(m_queue.front());
        m_queue.pop();
    }
    return true;
}

bool PacketQueue::is_empty() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_queue.empty();
}

size_t PacketQueue::get_size() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_queue.size();
}
