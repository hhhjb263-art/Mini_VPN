#ifndef TUN
#define TUN

#include "../Buffer/PacketBuffer.h"

class Tun{
private:
    int m_fd = -1;
    size_t Max_payload_len = 1400;
public:
    Tun();
    ~Tun();
    Tun(Tun &&other) noexcept;
    Tun &operator=(Tun &&other) noexcept;
    bool create_tun(const char *name);
    int get_fd() const;
    void close();
    bool setNoBlock();

    bool read_buf(packet_buffer &buf);
    bool write_buf(const packet_buffer &buf);
};

#endif
