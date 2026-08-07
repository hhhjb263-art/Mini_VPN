#pragma once
#include<iphlpapi.h>
#include<Windows.h>
#include<string>
#include "tun_macro.h"


// Wintun网卡IP/网络参数配置类，用来给虚拟网卡设置地址、MTU、DNS、跃点等
class AdapterConfig{
public:
	explicit AdapterConfig(NET_LUID interfaceLuid);
	AdapterConfig& operator=(const AdapterConfig&) = delete;
	AdapterConfig(const AdapterConfig&) = delete;

	bool set_IPv4_address(const std::wstring &ipAddress, uint8_t prefixLenth);
	bool remove_IPv4_address(const std::wstring &ipAddress, uint8_t prefixLenth);
	bool set_MTU(uint32_t mtu); //1420
	bool set_metric(uint8_t metric);
	bool set_DNS_IPv4(const std::wstring &dnsServer);

private:
	NET_LUID m_interfaceLuid{};
};

