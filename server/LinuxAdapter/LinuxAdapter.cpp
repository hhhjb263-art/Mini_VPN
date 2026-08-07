#include "LinuxAdapter.h"
#include <cstring>
#include <cerrno>
#include <cstdio>
#include <cstdint>

#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <linux/if.h>
#include <arpa/inet.h>
#include <net/route.h>

int LinuxAdapter::get_ifindex(const std::string &dev)
{
    if(!is_valid()){
        return -1;
    }
    struct ifreq ifr{};
    strncpy(ifr.ifr_name,dev.c_str(),IFNAMSIZ -1);
    ifr.ifr_name[IFNAMSIZ -1] = '\0';
    if(ioctl(m_sock,SIOCGIFINDEX,&ifr) < 0){
        fprintf(stderr, "SIOCGIFINDEX %s failed: %s\n", dev.c_str(), strerror(errno));
        return -1;
    }
    return ifr.ifr_ifindex;
}
bool LinuxAdapter::is_valid() const
{
    return m_sock >= 0;
}
bool LinuxAdapter::fill_route(rtentry &rt, const std::string &dest, int prefix, const std::string &dev)
{
    memset(&rt,0,sizeof(rt));
    struct sockaddr_in * dst = reinterpret_cast<struct sockaddr_in *> (&rt.rt_dst);
    dst->sin_family = AF_INET;
    if(inet_pton(AF_INET,dest.c_str(),&dst->sin_addr) <= 0){
        fprintf(stderr, "route invalid dest ip: %s\n", dest.c_str());
        return false;
    }

    if(prefix < 0 || prefix >32 ) 
        return false;
    struct sockaddr_in *mask = reinterpret_cast<struct sockaddr_in *>(&rt.rt_genmask);
    mask->sin_family = AF_INET;
    uint32_t num_mask = prefix == 0 ? 0U : (0xFFFFFFFFU << (32U - static_cast<uint32_t>(prefix)));
    mask->sin_addr.s_addr = htonl(num_mask);

    // 出口网卡索引
    strncpy(rt.rt_dev,dev.c_str(),ALTIFNAMSIZ -1);
    rt.rt_dev[ALTIFNAMSIZ -1] = '\0';

    rt.rt_flags = RTF_UP | RTF_HOST;
    return true;
}
LinuxAdapter::LinuxAdapter()
{
    m_sock = socket(AF_INET,SOCK_DGRAM,0);
    if(m_sock < 0){
        fprintf(stderr, "create socket failed: %s\n", strerror(errno));
    }
}

LinuxAdapter::~LinuxAdapter()
{
    if(m_sock >= 0){
        close(m_sock);
        m_sock = -1;
    }
}

LinuxAdapter &LinuxAdapter::operator=(LinuxAdapter &&other) noexcept
{
    if(this != &other){
        if(m_sock >= 0 )
            ::close(m_sock);
        this->m_sock = other.m_sock;
        other.m_sock = -1;
    }
    return *this;
}

LinuxAdapter::LinuxAdapter(LinuxAdapter &&other) noexcept
{
    this->m_sock = other.m_sock;
    other.m_sock =-1;
}

bool LinuxAdapter::set_address(const std::string &dev, const std::string &ip, int prefix)
{
    if(!is_valid())
        return false;
    struct ifreq ifr{};

    strncpy(ifr.ifr_name,dev.c_str(),IFNAMSIZ -1);
    ifr.ifr_name[IFNAMSIZ -1] = '\0';
    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    if(inet_pton(AF_INET,ip.c_str(),&addr.sin_addr) <= 0){
        fprintf(stderr, "invalid ip: %s\n", ip.c_str());
        return false;
    }
    std::memcpy(&ifr.ifr_addr,&addr,sizeof(addr));   

    if(ioctl(m_sock,SIOCSIFADDR,&ifr) < 0){
        fprintf(stderr, "set ip %s failed: %s\n", ip.c_str(), strerror(errno));
        return false;
    }

    uint32_t mask_num;
    if(prefix < 0 || prefix > 32){
        return false;
    }
    if (prefix == 0 ){
        mask_num = 0U;
    }
    else{
        mask_num = 0xFFFFFFFFU << (32U - static_cast<uint32_t>(prefix));
    }
    struct sockaddr_in addr_mask{};
    addr_mask.sin_family = AF_INET;
    addr_mask.sin_addr.s_addr = htonl(mask_num);
    std::memcpy(&ifr.ifr_netmask,&addr_mask,sizeof(addr_mask));
    if(ioctl(m_sock,SIOCSIFNETMASK,&ifr) < 0){
        fprintf(stderr, "SIOCSIFNETMASK /%d failed: %s\n", prefix, strerror(errno));
        return false;
    }
    return true;
}

bool LinuxAdapter::set_mtu(const std::string &dev, int mtu)
{
    if(!is_valid())
        return false;
    struct ifreq ifr{};
    strncpy(ifr.ifr_name,dev.c_str(),IFNAMSIZ -1);
    ifr.ifr_name[IFNAMSIZ -1] = '\0';
    ifr.ifr_mtu = mtu;
    if(ioctl(m_sock,SIOCSIFMTU,&ifr) < 0){
        fprintf(stderr, "set mtu %d %s failed: %s\n", mtu, dev.c_str(), strerror(errno));
        return false;
    }
    return true;
}

bool LinuxAdapter::set_up(const std::string &dev)
{
    if(!is_valid())
        return false;
    
    struct ifreq ifr{};
    strncpy(ifr.ifr_name,dev.c_str(),IFNAMSIZ -1);
    ifr.ifr_name[IFNAMSIZ -1] = '\0';
    
    if(ioctl(m_sock,SIOCGIFFLAGS,&ifr) < 0){
        fprintf(stderr, "set up %s failed: %s\n", dev.c_str(), strerror(errno));
        return false;
    }
    ifr.ifr_flags |= IFF_UP;
    if(ioctl(m_sock,SIOCSIFFLAGS,&ifr) < 0){
        fprintf(stderr, "set up %s failed: %s\n", dev.c_str(), strerror(errno));
        return false;
    }
    return true;
}

bool LinuxAdapter::set_down(const std::string &dev)
{
    if(!is_valid())
        return false;
    struct ifreq ifr{};
    strncpy(ifr.ifr_name,dev.c_str(),IFNAMSIZ -1);
    ifr.ifr_name[IFNAMSIZ -1 ] = '\0';
    if(ioctl(m_sock,SIOCSIFFLAGS,&ifr) < 0){
        fprintf(stderr, "set down %s failed: %s\n", dev.c_str(), strerror(errno));
        return false;
    }
    ifr.ifr_flags &=  ~IFF_UP;
    if(ioctl(m_sock,SIOCSIFFLAGS,&ifr) < 0){
        fprintf(stderr, "set down %s failed: %s\n", dev.c_str(), strerror(errno));
        return false;
    }
    return true;
}

bool LinuxAdapter::route_add(const std::string &dest, int prefix, const std::string &dev)
{
    if(!is_valid())
        return false;
    if(prefix < 0 || prefix >32){
        fprintf(stderr, "route prefix invalid %d\n", prefix);
        return false;
    }
    rtentry rt{};
    int ifindex = get_ifindex(dev);
    if(ifindex < 0)
        return false;
    if(!fill_route(rt,dest.c_str(),ifindex,dev)){
        return false;
    }
    // add to route
    if(ioctl(m_sock,SIOCADDRT,&rt) < 0){
        fprintf(stderr, "SIOCADDRT add %s/%d failed: %s\n", dest.c_str(), prefix, strerror(errno));
        return false;
    }
    return true;
}

bool LinuxAdapter::route_del(const std::string &dest, int prefix)
{
    if(!is_valid())
        return false;
    if(prefix < 0 || prefix >32)
        return false;
    rtentry rt{};
    memset(&rt,0,sizeof(rt));
    struct sockaddr_in* dst = reinterpret_cast<struct sockaddr_in *> (&rt.rt_dst);
    dst->sin_family = AF_INET;
    if(inet_pton(AF_INET,dest.c_str(),&dst->sin_addr) < 0){
        fprintf(stderr, "route del invalid dest ip: %s\n", dest.c_str());
        return false;
    }
    struct sockaddr_in * mask = reinterpret_cast<struct sockaddr_in *> (&rt.rt_genmask);
    mask->sin_family = AF_INET;
    uint32_t mask_num = (prefix == 0) ? 0U : (0xFFFFFFFFU << (32U - static_cast<uint32_t>(prefix)));
    mask->sin_addr.s_addr = htonl(mask_num);
    if(ioctl(m_sock,SIOCDELRT,&rt) < 0){
        fprintf(stderr, "SIOCDELRT del %s/%d failed: %s\n", dest.c_str(), prefix, strerror(errno));
        return false;
    }
    return true;
}
