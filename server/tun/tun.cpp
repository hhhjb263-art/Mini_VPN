#include "tun.h"
#include <fcntl.h>
#include <unistd.h>
#include <cstring>
#include <cerrno>
#include <cstdio>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include<iostream>
#include"../Buffer/PacketBuffer.h"

Tun::Tun()
{
}

Tun::~Tun()
{
    close();
}

Tun::Tun(Tun &&other) noexcept
{
    m_fd = other.m_fd;
    other.m_fd = -1;
}

Tun &Tun::operator=(Tun &&other) noexcept
{
    if(this != &other){
        close();
        this->m_fd = other.m_fd;
        other.m_fd = -1;
    }
    return *this;
    // TODO: 在此处插入 return 语句
}

bool Tun::create_tun(const char *name)
{
    if(m_fd >= 0){
        std::cout<<"tun was opened" << m_fd <<std::endl;
        return false;
    }
    m_fd = open("/dev/net/tun",O_RDWR);
    if(m_fd < 0){
        std::cout<< "tun open failed " << std::endl;
        return false;
    }
    struct ifreq ifr{};
    ifr.ifr_flags =IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name,name,IFNAMSIZ -1);
    ifr.ifr_name[IFNAMSIZ -1] = '\0';
    if(ioctl(m_fd,TUNSETIFF,&ifr) < 0){
         fprintf(stderr, "[TUN ERROR] TUNSETIFF ioctl failed: %s\n", strerror(errno));
        // 创建失败，关闭打开的fd并重置
        ::close(m_fd);
        m_fd = -1;
        return false;
    }
    return true;
}

int Tun::get_fd() const
{
    return m_fd;
}

void Tun::close()
{
    if(m_fd>0){
        ::close(m_fd);
        m_fd = -1;
    }
}

bool Tun::setNoBlock()
{
    if(m_fd < 0){
        return false;
    }
    int flags = fcntl(m_fd,F_GETFL,0);
    if(flags == -1){
        return false;
    }
    return fcntl(m_fd,F_SETFL,flags | O_NONBLOCK) != -1;
}

bool Tun::read_buf(packet_buffer &buf)
{
    if(m_fd < 0)
        return false;
        
    buf.resize(Max_payload_len);

    ssize_t ret = ::read(m_fd, buf.data(), Max_payload_len);
    if(ret <= 0){
        buf.clear();
        return false;
    }

    // 按实际读取字节 resize
    buf.resize(static_cast<size_t>(ret));
    buf.set_direction(PacketDirection::TuntoNetwork);
    return true;
}

bool Tun::write_buf(const packet_buffer &buf)
{
    if(m_fd < 0 || buf.is_empty())
        return false;

    ssize_t ret = ::write(m_fd, buf.get_data(), buf.data_size());
    return ret > 0;
}
