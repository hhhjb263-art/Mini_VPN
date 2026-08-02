#include <iostream>
#include <string>
#include <thread>
#include <atomic>
#include <mutex>
#include <chrono>
#include <cstdint>
#include <exception>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <Windows.h>

#include "UDP.h"
#include "tun.h"
#include "AdapterConfig.h"
#include "route_manager.h"
#include "reconnect_manager.h"

#pragma comment(lib, "Ws2_32.lib")


static std::wstring to_wstring(const std::string& str)
{
    return std::wstring(str.begin(), str.end());
}

namespace
{
    constexpr const char* kDefaultServer = "47.238.231.170";
    constexpr uint16_t kDefaultPort = 51820;

    std::atomic<bool> g_running{ true };
    std::once_flag g_shutdownFlag;
    RouteManager* g_route = nullptr;
    ReconnectManager* g_mgr = nullptr;

    // 唯一清理入口：正常退出、Ctrl+C、关闭窗口、异常捕获都走这里，只执行一次
    void request_shutdown()
    {
        std::call_once(g_shutdownFlag, []()
            {
                std::cout << "\n正在退出，清理虚拟网卡路由...\n";
                g_running.store(false);
                if (g_mgr)
                {
                    g_mgr->stop();
                }
                if (g_route)
                {
                    g_route->clear_routes();
                }
            });
    }

    // Ctrl+C / Ctrl+Break / 关闭窗口 / 关机：先清理再退出，避免路由残留
    BOOL WINAPI console_ctrl_handler(DWORD ctrlType)
    {
        if (ctrlType == CTRL_C_EVENT || ctrlType == CTRL_BREAK_EVENT ||
            ctrlType == CTRL_CLOSE_EVENT || ctrlType == CTRL_SHUTDOWN_EVENT)
        {
            request_shutdown();
            ::ExitProcess(0);
        }
        return TRUE;
    }

    bool parse_port(const std::string& text, uint16_t& out)
    {
        try
        {
            const int v = std::stoi(text);
            if (v < 1 || v > 65535)
            {
                return false;
            }
            out = static_cast<uint16_t>(v);
            return true;
        }
        catch (const std::exception&)
        {
            return false;
        }
    }

    bool is_valid_ipv4(const std::string& ip)
    {
        IN_ADDR addr{};
        std::wstring w = to_wstring(ip);
        return ::InetPtonW(AF_INET, w.c_str(), &addr) == 1;
    }

    void print_usage(const char* exe)
    {
        std::cerr << "用法: " << exe << " [服务器IP] [端口]\n"
                  << "  默认: " << kDefaultServer << ":" << kDefaultPort << "\n"
                  << "  示例: " << exe << " 47.238.231.170 51820\n"
                  << "  运行后输入 r 回车可模拟断线测试重连，回车/关闭窗口退出\n";
    }
}

int main(int argc, char** argv)
{

    std::string remote = kDefaultServer;
    uint16_t port = kDefaultPort;
    if (argc > 1)
    {
        remote = argv[1];
        if (!is_valid_ipv4(remote))
        {
            std::cerr << "无效的服务器 IP: " << remote << "\n";
            print_usage(argv[0]);
            return 1;
        }
    }
    if (argc > 2 && !parse_port(argv[2], port))
    {
        std::cerr << "无效的端口: " << argv[2] << "（有效范围 1-65535）\n";
        print_usage(argv[0]);
        return 1;
    }

    std::cout << "VPN 客户端启动，目标服务器 " << remote << ":" << port << "\n";


    ::SetConsoleCtrlHandler(console_ctrl_handler, TRUE);

    try
    {
        WintunTun tun;
        if (!tun.init_tun("MyTunAdapter", "MyTunnel"))
        {
            std::cerr << "Wintun初始化失败（请以管理员身份运行，且 wintun.dll 位于 exe 同目录）\n";
            return 1;
        }

        NET_LUID luid = tun.get_interface_luid();
        AdapterConfig adapter(luid);
        if (!adapter.set_IPv4_address(L"10.8.0.2", 24))
        {
            std::cerr << "设置TUN IP失败\n";
            return 1;
        }
        if (!adapter.set_MTU(1400))
        {
            std::cerr << "[警告] 设置MTU失败\n";
        }
        if (!adapter.set_metric(5))
        {
            std::cerr << "[警告] 设置接口跃点失败\n";
        }
        if (!adapter.set_DNS_IPv4(L"8.8.8.8,1.1.1.1"))
        {
            std::cerr << "[警告] 设置DNS失败，域名解析仍走本地DNS\n";
        }

        RouteManager route(luid);
        g_route = &route;
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

        ReconnectManager mgr(remote, port, 256);
        g_mgr = &mgr;
        mgr.set_state_callback([](ConnState s)
            {
                std::cout << "[Reconnect] 状态 -> " << ReconnectManager::state_name(s) << std::endl;
            });
        mgr.set_connected_callback([&]()
            {
                // 每次连接建立后，确认路由仍然生效
                route.add_server_bypass_route(to_wstring(remote));
                route.add_default_route(5);
                std::cout << "[Reconnect] 连接建立，路由已确认\n";
            });
        if (!mgr.start())
        {
            std::cerr << "重连状态机启动失败\n";
            return 1;
        }

        /*  TUN <-> UDP 泵线程 */
        std::thread tun_to_udp([&]()
            {
                while (g_running.load())
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

        std::thread udp_to_tun([&]()
            {
                while (g_running.load())
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
                        continue; 
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
                  << "直接回车 / 关闭窗口 / Ctrl+C：退出\n";


        std::string line;
        while (g_running.load() && std::getline(std::cin, line))
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

        request_shutdown();
        if (tun_to_udp.joinable())
        {
            tun_to_udp.join();
        }
        if (udp_to_tun.joinable())
        {
            udp_to_tun.join();
        }
        std::cout << "VPN退出\n";
    }
    catch (const std::exception& e)
    {
        std::cerr << "异常:" << e.what() << std::endl;
        request_shutdown();
        return 1;
    }

    return 0;
}
