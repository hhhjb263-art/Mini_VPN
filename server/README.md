# VPN Server（Linux 服务端）

基于 **TUN 虚拟网卡 + UDP 隧道** 的 VPN 服务端。

> 本分支为 **server（服务端）** 版本，运行于 Linux。
> 客户端版本请参考仓库其他分支（如 `dev` 的 Windows/Wintun 实现）。

## 目录结构

```
Buffer/         数据缓冲（PacketBuffer / QueueBuffer）与隧道协议头
UDP/            UDP 传输层（三次握手 / 心跳保活 / 收发线程）
tun/            TUN 虚拟网卡读写
LinuxAdapter/   网卡 IP / MTU / 路由配置
core/           VpnCore 转发层（TUN ↔ UDP 桥接）
main.cpp        服务端入口（CLI 解析 + 信号处理）
```

## 构建

```bash
cmake -S . -B build
cmake --build build
```

## 运行（需要 root 权限创建 TUN）

```bash
sudo ./build/vpn_server -a 10.8.0.1 -p 51820 --default-route
```

### 命令行参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `-l, --listen <ip>` | 监听 IP | `0.0.0.0` |
| `-p, --port <port>` | 监听端口 | `51820` |
| `-n, --name <name>` | TUN 网卡名 | `vpn0` |
| `-a, --addr <ip>` | 隧道内网 IP | `10.8.0.1` |
| `--prefix <n>` | 隧道网段前缀 | `24` |
| `--mtu <n>` | TUN MTU | `1400` |
| `--default-route` | 把默认路由指向 TUN | 关 |

## 隧道协议

- 报文头：`magic(4) + version(1) + type(1) + payload_len(2) + sequence(4)`
- 三次握手：SYN → SYN+ACK → ACK
- 心跳保活：每 10s 发送，30s 未响应判定失联
