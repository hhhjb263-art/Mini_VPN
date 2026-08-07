#include "VpnCore.h"

#include <csignal>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>

// 全局：信号处理只置位标志，主线程负责优雅停止
static volatile std::sig_atomic_t g_stop = 0;

static void handle_signal(int sig)
{
    (void)sig;
    g_stop = 1;
}

static void print_usage(const char *prog)
{
    printf("用法: %s [选项]\n", prog);
    printf("  服务端 VPN：创建 TUN 虚拟网卡并通过 UDP 隧道转发流量\n");
    printf("选项:\n");
    printf("  -l, --listen <ip>     监听 IP (默认 0.0.0.0)\n");
    printf("  -p, --port <port>     监听端口 (默认 51820)\n");
    printf("  -n, --name <name>     TUN 网卡名 (默认 vpn0)\n");
    printf("  -a, --addr <ip>       TUN 内网 IP (默认 10.8.0.1)\n");
    printf("      --prefix <n>      隧道网段前缀 (默认 24)\n");
    printf("      --mtu <n>         TUN MTU (默认 1400)\n");
    printf("      --default-route   把默认路由指向 TUN\n");
    printf("  -k, --key <path>      服务端 X25519 私钥 (默认 keys/server.key)\n");
    printf("  -h, --help            显示本帮助\n");
}

static bool parse_args(int argc, char *argv[], VpnCore::Config &cfg)
{
    for(int i = 1; i < argc; ++i){
        const std::string arg = argv[i];
        auto next = [&](const char *what) -> const char * {
            if(i + 1 >= argc){
                fprintf(stderr, "缺少参数: %s %s\n", arg.c_str(), what);
                return nullptr;
            }
            return argv[++i];
        };

        if(arg == "-h" || arg == "--help"){
            print_usage(argv[0]);
            exit(0);
        }else if(arg == "-l" || arg == "--listen"){
            const char *v = next("IP");
            if(!v) return false;
            cfg.listen_ip = v;
        }else if(arg == "-p" || arg == "--port"){
            const char *v = next("端口");
            if(!v) return false;
            cfg.listen_port = static_cast<uint16_t>(std::atoi(v));
        }else if(arg == "-n" || arg == "--name"){
            const char *v = next("网卡名");
            if(!v) return false;
            cfg.tun_name = v;
        }else if(arg == "-a" || arg == "--addr"){
            const char *v = next("IP");
            if(!v) return false;
            cfg.tun_ip = v;
        }else if(arg == "--prefix"){
            const char *v = next("前缀");
            if(!v) return false;
            cfg.tun_prefix = std::atoi(v);
        }else if(arg == "--mtu"){
            const char *v = next("MTU");
            if(!v) return false;
            cfg.tun_mtu = std::atoi(v);
        }else if(arg == "--default-route"){
            cfg.add_default_route = true;
        }else if(arg == "-k" || arg == "--key"){
            const char *v = next("路径");
            if(!v) return false;
            cfg.key_path = v;
        }else{
            fprintf(stderr, "未知选项: %s\n", arg.c_str());
            print_usage(argv[0]);
            return false;
        }
    }
    return true;
}

int main(int argc, char *argv[])
{
    VpnCore::Config cfg;
    if(!parse_args(argc, argv, cfg)){
        return 1;
    }

    VpnCore core;
    if(!core.init(cfg)){
        fprintf(stderr, "[main] 初始化失败（创建 TUN 需要 root 权限）\n");
        return 1;
    }
    if(!core.start()){
        fprintf(stderr, "[main] 启动转发层失败\n");
        core.stop();
        return 1;
    }

    printf("[main] VPN 服务端已启动: listen=%s:%u tun=%s(%s/%d mtu=%d)\n",
           cfg.listen_ip.c_str(), cfg.listen_port,
           cfg.tun_name.c_str(), cfg.tun_ip.c_str(),
           cfg.tun_prefix, cfg.tun_mtu);
    printf("[main] 按 Ctrl+C 优雅退出\n");

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    // 阻塞等待信号
    while(!g_stop){
        pause();
    }

    core.stop();
    printf("[main] VPN 服务端已退出\n");
    return 0;
}
