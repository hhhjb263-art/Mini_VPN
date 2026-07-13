#pragma once
#include"itun_device.h"
#include"wintun-0.14.1/wintun/include/wintun.h"
/*
*	使用 wintun.h 官方声明的函数类型。
	详见wintun-0.14.1/wintun/include/wintun.h源码
*/
class WintunTun : public ITunDevice{
public:
	WintunTun() = default;
	~WintunTun();

	WintunTun(const WintunTun&) = delete;
	WintunTun& operator=(const WintunTun&) = delete;

	bool init_tun(const std::string &TunName,const std::string &tunnelType) override;
	uint8_t *read_packet(DWORD* outPackLen) override;
	void release_read_packet(const uint8_t * pkt) override;
	bool write_packet(const uint8_t * RawIPdata , DWORD len) override;
	NET_LUID get_interface_luid() const override;
	bool is_ready() const override;
protected:
	void cleanup_resource() override;
private:
	bool load_wintun_api();
	bool open_or_create_adapter(const std::wstring &TunName, const std::wstring &tunnelType);
	bool fetch_adapter_luid();
	void reset_api_pointers() noexcept; // 无需抛出异常
private:
	HMODULE m_hDll = nullptr;
	WINTUN_ADAPTER_HANDLE m_hAdapter = nullptr;
	WINTUN_SESSION_HANDLE m_hsession = nullptr;
	NET_LUID m_ifliud = { };
	bool m_bInited = false;
private:
	WINTUN_CREATE_ADAPTER_FUNC * m_fnCreateAdapter = nullptr;
	WINTUN_OPEN_ADAPTER_FUNC * m_fnOpenAdapter = nullptr;
	WINTUN_CLOSE_ADAPTER_FUNC * m_fnCloseAdapter = nullptr;
	WINTUN_GET_ADAPTER_LUID_FUNC * m_fnGetAdapterLuid = nullptr;

	WINTUN_START_SESSION_FUNC * m_fnStartSession = nullptr;
	WINTUN_END_SESSION_FUNC * m_fnEndSession = nullptr;
	WINTUN_RECEIVE_PACKET_FUNC * m_fnReceivePacket = nullptr;
	WINTUN_RELEASE_RECEIVE_PACKET_FUNC * m_fnReleaseReceivePacket = nullptr;

	WINTUN_ALLOCATE_SEND_PACKET_FUNC * m_fnAllocateSendPacket = nullptr;
	WINTUN_SEND_PACKET_FUNC* m_fnSendPacket = nullptr;
};