#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>
#pragma comment(lib, "iphlpapi.lib")


struct Ipv4RouteParam{
	std::wstring destination;
	uint8_t prefixLength = 0;
	std::wstring nexthop;
	NET_LUID interfaceLuid{};
	uint32_t metric = 0;
};

class RouteManager final
{
public:
	explicit RouteManager(NET_LUID tunnelLuid);
	~RouteManager();

	bool add_ipv4_route(const Ipv4RouteParam& param);
	bool add_tunnel_route(
		const std::wstring& destination,
		uint8_t prefixLength,
		uint32_t metric);

	bool add_default_route(uint32_t metric);
	bool add_server_bypass_route(const std::wstring& serverIp);
	void clear_routes() noexcept;
private:
	bool create_route(const MIB_IPFORWARD_ROW2& route);
private:
	NET_LUID m_tunnelLuid{};
	std::vector<MIB_IPFORWARD_ROW2> m_createdRoutes;
};

