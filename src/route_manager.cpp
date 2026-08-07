#include "route_manager.h"

namespace {
	bool parse(const std::wstring& text, IN_ADDR &out) {
		out = {};
		const INT result = ::InetPtonW(AF_INET,text.c_str(),&out);
		return result == 1;
	}
	bool make_ipv4_to_sockaddr(const std::wstring& ip, SOCKADDR_INET& out) {
		out = {};
		out.Ipv4.sin_family = AF_INET;
		out.Ipv4.sin_port = 0;
		return parse(ip,out.Ipv4.sin_addr);
	}
}

RouteManager::RouteManager(
	NET_LUID tunnelLuid
)
	: m_tunnelLuid(tunnelLuid)
{
}

RouteManager::~RouteManager()
{
	clear_routes();
}

bool RouteManager::add_ipv4_route(const Ipv4RouteParam& param)
{
	if (param.destination.empty() || 
		param.nexthop.empty() ||
		param.prefixLength > 32 || 
		param.interfaceLuid.Value == 0) {

		return false;
	}
	MIB_IPFORWARD_ROW2 row2{};
	InitializeIpForwardEntry(&row2);
	row2.InterfaceLuid = m_tunnelLuid;
	row2.DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
	if (!parse(param.destination, row2.DestinationPrefix.Prefix.Ipv4.sin_addr)) {
		::SetLastError(ERROR_INVALID_PARAMETER);
		return false;
	}
	row2.DestinationPrefix.PrefixLength = param.prefixLength;
	row2.NextHop.Ipv4.sin_family = AF_INET;
	if (!parse(param.nexthop,row2.NextHop.Ipv4.sin_addr)) {
		::SetLastError(ERROR_INVALID_PARAMETER);
		return false;
	}
	row2.Metric = param.metric;
	return create_route(row2);
}

bool RouteManager::add_tunnel_route(const std::wstring& destination,
	uint8_t prefixLength,uint32_t metric)
{
	if (m_tunnelLuid.Value == 0) {
		::SetLastError(ERROR_INVALID_HANDLE);
		return false;
	}
	Ipv4RouteParam param;
	param.destination = destination;
	param.prefixLength = prefixLength;
	param.metric = metric;
	param.nexthop = L"0.0.0.0";
	param.interfaceLuid = m_tunnelLuid;
	return add_ipv4_route(param);
}

bool RouteManager::add_default_route(uint32_t metric)
{
	return add_tunnel_route(L"0.0.0.0",0,metric);
}

bool RouteManager::add_server_bypass_route(const std::wstring& serverIp)
{
	SOCKADDR_INET destination{};
	if (!make_ipv4_to_sockaddr(serverIp, destination)) {
		::SetLastError(ERROR_INVALID_PARAMETER);
		return false;
	}
	MIB_IPFORWARD_ROW2 bestRoute{};
	SOCKADDR_INET bestSource{};
	NETIO_STATUS status = ::GetBestRoute2(nullptr,0,nullptr,&destination,0,&bestRoute,&bestSource);
	if (status != NO_ERROR)
	{
		::SetLastError(status);
		return false;
	}
	MIB_IPFORWARD_ROW2 bypass_row2{};
	InitializeIpForwardEntry(&bypass_row2);
	bypass_row2.InterfaceLuid = bestRoute.InterfaceLuid;
	bypass_row2.DestinationPrefix.Prefix = destination;
	bypass_row2.DestinationPrefix.PrefixLength = 32;
	bypass_row2.NextHop = bestRoute.NextHop;
	bypass_row2.Metric = 0;
	return create_route(bypass_row2);
}

void RouteManager::clear_routes() noexcept
{
	for (auto it = m_createdRoutes.rbegin(); it != m_createdRoutes.rend(); it++) {
		::DeleteIpForwardEntry2(&(*it));
	}
	m_createdRoutes.clear();
}

bool RouteManager::create_route(const MIB_IPFORWARD_ROW2& route)
{
	NETIO_STATUS status = CreateIpForwardEntry2(&route);
	if (status == NO_ERROR) {
		m_createdRoutes.push_back(route);
		return true;
	}
	if (status == ERROR_OBJECT_ALREADY_EXISTS) {
		return true;
	}
	::SetLastError(status);
	return false;
}
