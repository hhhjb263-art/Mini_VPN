#include <iostream>
#include <string>
#include <thread>
#include <atomic>
#include <mutex>
#include <chrono>
#include <cstdint>
#include <exception>
#include <fstream>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <Windows.h>

#include "UDP.h"
#include "tun.h"
#include "AdapterConfig.h"
#include "route_manager.h"
#include "reconnect_manager.h"
#include "Crypt.h"
#include <memory>

#pragma comment(lib, "Ws2_32.lib")


static std::wstring to_wstring(const std::string& str)
{
    return std::wstring(str.begin(), str.end());
}

namespace
{
    constexpr const char* kDefaultServer = "38.76.211.127";
    constexpr uint16_t kDefaultPort = 51820;

    std::atomic<bool> g_running{ true };
    std::once_flag g_shutdownFlag;
    RouteManager* g_route = nullptr;
    ReconnectManager* g_mgr = nullptr;

    // ??????:?????Ctrl+C??????????????,?????
    void request_shutdown()
    {
        std::call_once(g_shutdownFlag, []()
            {
                std::cout << "\n????,????????...\n";
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

    // Ctrl+C / Ctrl+Break / ???? / ??:??????,??????
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
        std::cerr << "??: " << exe << " [???IP] [??]\n"
                  << "  ??: " << kDefaultServer << ":" << kDefaultPort << "\n"
                  << "  ??: " << exe << " 38.76.211.127 51820\n"
                  << "  ????? r ???????????,??/??????\n";
    }
}

// Resolve key files relative to the exe directory (admin runs may change cwd).
static std::string get_exe_dir()
{
    wchar_t buffer[MAX_PATH]{};
    const DWORD n = ::GetModuleFileNameW(nullptr, buffer, MAX_PATH);
    if (n == 0 || n >= MAX_PATH)
    {
        return "";
    }
    const std::wstring path(buffer, n);
    const std::size_t slash = path.find_last_of(L"\\/");
    if (slash == std::wstring::npos)
    {
        return "";
    }
    std::string result;
    result.reserve(slash + 1);
    for (std::size_t i = 0; i <= slash; ++i)
    {
        result.push_back(static_cast<char>(path[i]));
    }
    return result;
}

// Look for the key file next to the exe, then in the keys\\ subfolder.
static std::string find_key_file(const std::string& exe_dir, const std::string& filename)
{
    const std::string candidates[] = {
        exe_dir + filename,
        exe_dir + "keys\\" + filename
    };
    for (const auto& candidate : candidates)
    {
        if (std::ifstream probe{candidate, std::ios::binary})
        {
            return candidate;
        }
    }
    return exe_dir + filename;
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
            std::cerr << "?????? IP: " << remote << "\n";
            print_usage(argv[0]);
            return 1;
        }
    }
    if (argc > 2 && !parse_port(argv[2], port))
    {
        std::cerr << "?????: " << argv[2] << "(???? 1-65535)\n";
        print_usage(argv[0]);
        return 1;
    }

    std::cout << "VPN ?????,????? " << remote << ":" << port << "\n";

    // ?? X25519 ??:client.key(?????)+ server.pub(?????),? exe ???
    std::shared_ptr<EVP_PKEY> priv_key;
    std::shared_ptr<EVP_PKEY> peer_pub;
    try
    {
        const std::string exe_dir = get_exe_dir();
        const std::string priv_path = find_key_file(exe_dir, "client.key");
        priv_key.reset(load_x25519_private_key(priv_path), EVP_PKEY_free);
        const std::string pub_path = find_key_file(exe_dir, "server.pub");
        peer_pub.reset(load_x25519_public_key(pub_path), EVP_PKEY_free);
    }
    catch (const std::exception& e)
    {
        std::cerr << "??????: " << e.what() << "\n"
                  << "???????:client.key(??)+ server.pub(?????)?? exe ???\n";
        return 1;
    }


    ::SetConsoleCtrlHandler(console_ctrl_handler, TRUE);

    try
    {
        WintunTun tun;
        if (!tun.init_tun("MyTunAdapter", "MyTunnel"))
        {
            std::cerr << "Wintun?????(?????????,? wintun.dll ?? exe ???)\n";
            return 1;
        }

        NET_LUID luid = tun.get_interface_luid();
        AdapterConfig adapter(luid);
        if (!adapter.set_IPv4_address(L"10.8.0.2", 24))
        {
            std::cerr << "??TUN IP??\n";
            return 1;
        }
        if (!adapter.set_MTU(1400))
        {
            std::cerr << "[??] ??MTU??\n";
        }
        if (!adapter.set_metric(5))
        {
            std::cerr << "[??] ????????\n";
        }
        if (!adapter.set_DNS_IPv4(L"8.8.8.8,1.1.1.1"))
        {
            std::cerr << "[??] ??DNS??,????????DNS\n";
        }

        RouteManager route(luid);
        g_route = &route;
        if (!route.add_server_bypass_route(to_wstring(remote)))
        {
            std::cerr << "???????????\n";
            return 1;
        }
        if (!route.add_default_route(5))
        {
            std::cerr << "????????\n";
            return 1;
        }

        ReconnectManager mgr(remote, port, 256, priv_key, peer_pub);
        g_mgr = &mgr;
        mgr.set_state_callback([](ConnState s)
            {
                std::cout << "[Reconnect] ?? -> " << ReconnectManager::state_name(s) << std::endl;
            });
        mgr.set_connected_callback([&]()
            {
                // ???????,????????
                route.add_server_bypass_route(to_wstring(remote));
                route.add_default_route(5);
                std::cout << "[Reconnect] ????,?????\n";
            });
        if (!mgr.start())
        {
            std::cerr << "?????????\n";
            return 1;
        }

        /*  TUN <-> UDP ??? */
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

        std::cout << "VPN???\n"
                  << "??IP: 10.8.0.2\n"
                  << "???: " << remote << ":" << port << "\n"
                  << "?? r ???:????????\n"
                  << "???? / ???? / Ctrl+C:??\n";


        std::string line;
        while (g_running.load() && std::getline(std::cin, line))
        {
            if (line == "r" || line == "R")
            {
                std::cout << "?????,??????...\n";
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
        std::cout << "VPN??\n";
    }
    catch (const std::exception& e)
    {
        std::cerr << "??:" << e.what() << std::endl;
        request_shutdown();
        return 1;
    }

    return 0;
}
