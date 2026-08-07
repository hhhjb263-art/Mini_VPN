#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#define _WINSOCKAPI_
#include <winsock2.h>
#include <ntddndis.h>
#include "tun_macro.h"
#include <cstdint>
#include <windows.h>
#include <string>

class ITunDevice {
public:
	virtual ~ITunDevice() = default;

	virtual bool init_tun(const std::string& TunName, const std::string& tunnelType) = 0;
	virtual uint8_t* read_packet(DWORD* outPackLen) = 0; // 读取ip包
	virtual void release_read_packet(const uint8_t* pkt) = 0; //释放读取缓存区
	virtual bool write_packet(const uint8_t* rawIPdata, DWORD len) = 0; //IP 包写入 Windows 协议栈
	virtual NET_LUID get_interface_luid() const = 0; //获取网卡LUID，用于路由/IP配置   返回适配器的 LUID。
	virtual bool is_ready() const = 0;
protected:
	virtual void cleanup_resource() = 0;
};