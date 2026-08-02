#include <iostream>
#include <string>
#include <thread>
#include <atomic>
#include <chrono>

#include "UDP.h"
#include "tun.h"
#include "AdapterConfig.h"
#include "route_manager.h"
#include "reconnect_manager.h"

// 简单转换
static std::wstring to_wstring(const std::string& str)
{
    return std::wstring(str.begin(), str.end());
}

int main(int argc, char** argv)
{
    std::string remote = (argc > 1) ? argv[1] : "192.168.233.131";
    uint16_t port = (argc > 2) ? static_cast<uint16_t>(std::stoi(argv[2])) : 51820;

    try
    {
        /*
            1. 创建 Wintun
        */
        WintunTun tun;
        if (!tun.init_tun("MyTunAdapter", "MyTunnel"))
        {
            std::cerr << "Wintun初始化失败\n";
            return 1;
        }

        /*
            2. 配置虚拟网卡
        */
        NET_LUID luid = tun.get_interface_luid();
        AdapterConfig adapter(luid);
        if (!adapter.set_IPv4_address(L"10.8.0.2", 24))
        {
            std::cerr << "设置TUN IP失败\n";
            return 1;
        }
        adapter.set_MTU(1400);
        adapter.set_metric(5);

        /*
            3. 配置路由
        */
        RouteManager route(luid);
        if (!route.add_server_bypass_route(to_wstring(remote)))
        {
            std::cerr << "添加服务器绕过路由失败\n";
            return 1;
        }
        if (!route.add_default_route(5))
        {
            std::cerr << "添加默认路由失败\n";
            return 1;
        }

        /*
            4. 重连状态机（管理 UDP 隧道生命周期）
        */
        ReconnectManager mgr(remote, port, 256);
        mgr.set_state_callback([](ConnState s)
            {
                std::cout << "[Reconnect] 状态 -> " << ReconnectManager::state_name(s) << std::endl;
            });
        mgr.set_connected_callback([&]()
            {
                // 每次连接建立后，确认路由仍然生效（CreateIpForwardEntry2 幂等）
                route.add_server_bypass_route(to_wstring(remote));
                route.add_default_route(5);
                std::cout << "[Reconnect] 连接建立，路由已确认\n";
            });
        if (!mgr.start())
        {
            std::cerr << "重连状态机启动失败\n";
            return 1;
        }

        std::atomic<bool> running{ true };

        /*
            TUN -> UDP（仅在隧道已建立时转发）
        */
        std::thread tun_to_udp([&]()
            {
                while (running.load())
                {
                    auto u = mgr.udp();
                    if (!u || !u->is_handshaked())
                    {
                        std::this_thread::sleep_for(std::chrono::milliseconds(10));
                        continue;
                    }
                    DWORD len = 0;
                    uint8_t* pkt = tun.read_packet(&len);
                    if (pkt && len > 0)
                    {
                        std::cout << "Wintun RX " << len << " bytes\n";
                        packet_buffer buf(pkt, len);
                        tun.release_read_packet(pkt);
                        u->send_ip_packet(std::move(buf));
                    }
                    else
                    {
                        std::this_thread::sleep_for(std::chrono::milliseconds(5));
                    }
                }
            });

        /*
            UDP -> TUN（实例失效时继续取新实例，不退出）
        */
        std::thread udp_to_tun([&]()
            {
                while (running.load())
                {
                    auto u = mgr.udp();
                    if (!u)
                    {
                        std::this_thread::sleep_for(std::chrono::milliseconds(10));
                        continue;
                    }
                    packet_buffer buf;
                    if (!u->recv_ip_packet(buf))
                    {
                        continue; // 旧实例已停止（重连中），下一轮取新实例
                    }
                    if (!buf.is_empty())
                    {
                        std::cout << "UDP TX->TUN " << buf.data_size() << " bytes\n";
                        tun.write_packet(buf.get_data(), static_cast<DWORD>(buf.data_size()));
                    }
                }
            });

        std::cout << "VPN运行中\n"
                  << "虚拟IP: 10.8.0.2\n"
                  << "服务器: " << remote << ":" << port << "\n"
                  << "输入 r 并回车：模拟断线测试重连\n"
                  << "直接回车：退出\n";

        std::string line;
        while (std::getline(std::cin, line))
        {
            if (line == "r" || line == "R")
            {
                std::cout << "已模拟断线，观察重连日志...\n";
                mgr.force_disconnect_for_test();
            }
            else
            {
                break;
            }
        }

        /*
            停止
        */
        running.store(false);
        mgr.stop();
        if (tun_to_udp.joinable()) tun_to_udp.join();
        if (udp_to_tun.joinable()) udp_to_tun.join();
        route.clear_routes();
        std::cout << "VPN退出\n";
    }
    catch (const std::exception& e)
    {
        std::cerr << "异常:" << e.what() << std::endl;
        return 1;
    }

    return 0;
}