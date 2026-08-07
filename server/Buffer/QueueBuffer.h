#include "PacketBuffer.h"
#include <cstring> 
#include <mutex>
#include <condition_variable>
#include <cstddef>
#include<queue>

#include <utility>

class PacketQueue{
private:
    size_t Max_size{1024};
    std::queue<packet_buffer> m_queue;
    mutable std::mutex m_mutex;
    std::condition_variable m_condition;
    bool m_shutdown{false};
public:
    PacketQueue(size_t max_size = 1024);
    void set_max_size(size_t n);
    PacketQueue(PacketQueue&& other) noexcept;
    PacketQueue &operator=(PacketQueue&& other) noexcept;
    ~PacketQueue();
    void shutdown();
    bool push(packet_buffer &&buf);
    bool pop(packet_buffer &buf);
    bool is_empty() const;  
    size_t get_size() const;
};