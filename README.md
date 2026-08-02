# VPN_

## 项目要求与运行说明

此项目依赖下列文件与环境，确保在构建与运行前满足：

- **必要文件**
  - `.editorconfig`：项目格式化与编码风格规则（请在仓库根目录添加）。
  - `CONTRIBUTING.md`：贡献说明与代码规范（请在仓库根目录添加）。
  - `wintun.dll`：将官方发布的 `wintun.dll` 放在可执行文件旁或 `System32` 中以便动态加载（不要分发未经许可的驱动二进制）。

- **构建依赖**
  - Visual Studio 2019 / 2022 + Windows SDK
  - Windows Driver Kit（仅在需要自行构建驱动或示例驱动时）
  - 链接 WinSock：ws2_32.lib（项目中通过 `#pragma comment(lib, "ws2_32.lib")` 引用）

- **运行要求**
  - 在创建或加载 Wintun 适配器时通常需要管理员权限（安装/创建虚拟网卡或修改路由表时）。
  - 确保 `wintun.dll` 与项目 `wintun.h` 匹配版本，否则可能因符号缺失导致加载失败。

- **测试指引**
  1. 将 `wintun.dll` 放在可执行目录或 `C:\Windows\System32`。
  2. 在管理员命令提示符下运行程序，确认能成功创建/打开 Wintun 适配器（观察程序日志或调用 `WintunGetRunningDriverVersion`）。
  3. 使用本项目的 `main.cpp` 桥接逻辑：Wintun <-> UDP。并在远端运行配套 UDP 服务器或在本机做回显以验证数据流通。
  4. 用 Wireshark（Npcap）监听 Wintun 虚拟网卡或使用系统 `Get-NetAdapter` / `Get-NetIPAddress` 验证地址与路由配置。

- **注意事项**
  - 项目中包含来自 Wintun 的源代码与示例，应遵守对应许可证（Wintun 原始代码通常为 GPLv2；预编译二进制有不同许可）。在分发或合并代码前请确认许可证兼容性或咨询法律意见。
  - 建议在仓库根目录补充 `.editorconfig` 和 `CONTRIBUTING.md`，以统一团队编码风格和贡献流程。

## 其他信息

如需更多信息或支持，请查看项目的其他文档或联系维护者。