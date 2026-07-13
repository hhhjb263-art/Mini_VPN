#include <conio.h>
#include"tun.h"

int main()
{
    WintunTun tun;
    bool ok = tun.init_tun("MyTun", "Layer3");
    if (!ok)
    {
        printf("初始化失败\n");
        _getch();
        return 1;
    }

    LOG_INFO("VPN隧道已就绪，按任意键退出");
    DWORD pktLen = 0;
    while (true)
    {
        uint8_t* pkt = tun.read_packet(&pktLen);
        if (pkt != nullptr && pktLen > 0)
        {
            LOG_TRACE("收到IP数据包，长度：%lu", pktLen);
            // 这里可以添加转发逻辑
            tun.release_read_packet(pkt);
        }
        // 检测是否有按键，有按键跳出循环
        if (_kbhit())
            break;
        Sleep(10);
    }
    return 0;
}