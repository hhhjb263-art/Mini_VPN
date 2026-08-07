
#pragma once

#include<string>

class LinuxAdapter
{
private:
    int m_sock = -1;
private:
    int get_ifindex(const std::string &dev);
    bool is_valid() const;
    bool fill_route(struct rtentry &rt,const std::string &dest,int prefix,const std::string &dev);
public:
    LinuxAdapter();
    ~LinuxAdapter();

    LinuxAdapter(const LinuxAdapter&) = delete;
    LinuxAdapter &operator=(const LinuxAdapter &) = delete;
    LinuxAdapter &operator=(LinuxAdapter && other) noexcept;
    LinuxAdapter (LinuxAdapter && other) noexcept;

    bool set_address(const std::string &dev, const std::string &ip,int prefix);
    bool set_mtu(const std::string &dev,int mtu);
    bool set_up(const std::string &dev);
    bool set_down(const std::string &dev);
    bool route_add(const std::string &dest,int prefix,const std::string &dev);
    bool route_del(const std::string &dest,int prefix);

};

