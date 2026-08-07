#define NTDDI_VERSION NTDDI_WIN10
#define _WIN32_WINNT _WIN32_WINNT_WIN10

#include <winsock2.h>
#include <ws2tcpip.h>
#include "AdapterConfig.h"
#include <icmpapi.h>
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib") 

namespace {
	bool parse(const std::wstring& text, IN_ADDR* output) {
		*output = {};
		 const int  result = ::InetPtonW(AF_INET,text.c_str(),output);
		 // 1 = 转换成功
		 // 0 = 格式错误
		 // <0 = 系统错误
		 return result == 1;
	}
}
AdapterConfig::AdapterConfig(NET_LUID interfaceLuid): m_interfaceLuid(interfaceLuid) {

}
/*
 * @brief       为Wintun虚拟网卡配置静态IPv4单播地址
 * @param ipAddress    宽字符串IPv4地址（如 L"10.0.10.2"）
 * @param prefixLength  IPv4子网前缀长度（0~32，常用24=255.255.255.0）
 * @return      true=配置IP成功，false=参数非法/解析失败/系统配置失败
 *
 * 1. 基于网卡唯一LUID精准定位目标虚拟网卡，避免修改到物理网卡
 * 2. 将字符串IP转为系统内核识别的二进制网络序IP
 * 3. 填充网卡IP配置结构体，调用系统API写入静态IPv4地址
 */

bool AdapterConfig::set_IPv4_address(const std::wstring& ipAddress, uint8_t prefixLength)
{	
	if (m_interfaceLuid.Value == 0 || ipAddress.empty() || prefixLength > 32) {
		LOG_ERROR("set_IPv4_address failed");
		return false;
	}
    // https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_unicastipaddress_row
    MIB_UNICASTIPADDRESS_ROW row{};
    // Initialize to safe defaults if available
    ::InitializeUnicastIpAddressEntry(&row);

    // Fill required fields for IPv4
    row.InterfaceLuid = m_interfaceLuid;
    row.OnLinkPrefixLength = prefixLength;

    // Populate IPv4 socket address part
    row.Address.Ipv4.sin_family = AF_INET;;
    if (!parse(ipAddress, &(row.Address.Ipv4.sin_addr))) {
        LOG_ERROR("set_IPv4_address: parse ip failed %ls", ipAddress.c_str());
        return false;
    }
    //手动配置ip
    row.PrefixOrigin = IpPrefixOriginManual;
    row.SuffixOrigin = IpSuffixOriginManual;

    const NETIO_STATUS  status = CreateUnicastIpAddressEntry(&row); //指定网卡创建/写入静态IPv4单播地址
    if (status == NO_ERROR) {
        LOG_INFO("CreateUnicastIpAddressEntry success err=%lu", status);
        return true;
    }
    /*
        成功返回true
        存在也返回true
    */
    if (status == ERROR_OBJECT_ALREADY_EXISTS) {
        return true;
    }
    LOG_ERROR("CreateUnicastIpAddressEntry failed status=%lu", status);
    return false;
}
bool AdapterConfig::remove_IPv4_address(const std::wstring &ipAdress, uint8_t prefixLenth) {
    DWORD err = GetLastError();
    if (m_interfaceLuid.Value == 0 || ipAdress.empty() || prefixLenth > 32) {
        LOG_ERROR("remove_IPv4_address failed , err = %lu",err);
        return false;
    }
    MIB_UNICASTIPADDRESS_ROW row{};
    ::InitializeUnicastIpAddressEntry(&row);
    row.InterfaceLuid = m_interfaceLuid;
    row.OnLinkPrefixLength = prefixLenth;
    row.Address.Ipv4.sin_family = AF_INET;

    if (!parse(ipAdress, &row.Address.Ipv4.sin_addr)) {
        err = GetLastError();
        LOG_ERROR("remove_IPv4_address: parse ip failed , err = %lu", err);
        return false;
    }
    const NETIO_STATUS  status = ::DeleteUnicastIpAddressEntry(&row);
    if (status == NO_ERROR || status == ERROR_NOT_FOUND) {
        LOG_INFO("CreateUnicastIpAddressEntry success err=%lu", status);
        return true;
    }
    /*
        成功返回true
    */
    if (status == ERROR_OBJECT_ALREADY_EXISTS) {
        return true;
    }

    ::SetLastError(status);
    return false;
}

bool AdapterConfig::set_MTU(uint32_t mtu)
{
    if (m_interfaceLuid.Value == 0 || mtu < 576 || mtu > 1500)
    {
        LOG_ERROR("set_MTU invalid mtu=%u", mtu);
        return false;
    }
    ULONG ifIndex = 0;
    NETIO_STATUS status =
        ConvertInterfaceLuidToIndex(&m_interfaceLuid, &ifIndex);
    if (status != NO_ERROR)
    {
        LOG_ERROR("ConvertInterfaceLuidToIndex failed %lu", status);
        return false;
    }
    wchar_t cmd[256]{};
    swprintf_s(
        cmd,
        L"netsh interface ipv4 set subinterface %lu mtu=%u store=persistent",
        ifIndex,
        mtu
    );
    int ret = _wsystem(cmd);
    if (ret != 0)
    {
        LOG_ERROR("netsh set mtu failed ret=%d", ret);
        return false;
    }
    LOG_INFO("Set MTU success ifIndex=%lu mtu=%u", ifIndex, mtu);
    return true;
}
bool AdapterConfig::set_metric(uint8_t metric)
{
    if (m_interfaceLuid.Value == 0)
    {
        LOG_ERROR("set_metric invalid LUID");
        return false;
    }
    ULONG ifIndex = 0;
    NETIO_STATUS status =
        ConvertInterfaceLuidToIndex(
            &m_interfaceLuid,
            &ifIndex
        );
    if (status != NO_ERROR)
    {
        LOG_ERROR(
            "ConvertInterfaceLuidToIndex failed %lu",
            status
        );
        return false;
    }
    wchar_t cmd[256]{};
    swprintf_s(
        cmd,
        L"netsh interface ipv4 set interface %lu metric=%u",
        ifIndex,
        metric
    );
    int ret = _wsystem(cmd);
    if (ret != 0)
    {
        LOG_ERROR(
            "set metric failed ret=%d",
            ret
        );
        return false;
    }
    LOG_INFO(
        "Set interface metric success ifIndex=%lu metric=%u",
        ifIndex,
        metric
    );
    return true;
}
bool AdapterConfig::set_DNS_IPv4(const std::wstring& dnsServers)
{
    if (m_interfaceLuid.Value == 0) {
        ::SetLastError(ERROR_INVALID_PARAMETER);
        LOG_ERROR("set_DNS_IPv4 : m_interfaceLuid not found  -> ERROR_INVALID_PARAMETER");
        return false;
    }
    GUID interfaceGuid{};
    NETIO_STATUS status = ::ConvertInterfaceLuidToGuid(&m_interfaceLuid,&interfaceGuid);
    if (status != NO_ERROR) {
        ::SetLastError(status);
        return false;
    }
    DNS_INTERFACE_SETTINGS settings{};
    settings.Version = DNS_INTERFACE_SETTINGS_VERSION1;
    settings.Flags = DNS_SETTING_NAMESERVER;

    settings.NameServer = const_cast<PWSTR> (dnsServers.c_str());
    /*
    * dnsServers.c_str() 返回 const wchar_t*
    * 结构体NameServer字段类型是 PWSTR (wchar_t*)，非const
    * 但官方文档说明：SetInterfaceDnsSettings 只会读取字符串，不会修改、不释放内存
    * 因此 const_cast 剥离const限定是安全合法操作，无内存越界风险
    */
    status = ::SetInterfaceDnsSettings(interfaceGuid, &settings);
    if (status != NO_ERROR) {
        ::SetLastError(status);
        return false;
    }
    return true;
}
