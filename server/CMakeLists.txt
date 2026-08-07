cmake_minimum_required(VERSION 3.16)

project(VPN LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# 本项目仅支持 Linux（依赖 linux/if_tun.h、linux/route.h 等内核头文件）
if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "This project only supports Linux")
endif()

# ============================================================
# 1) 模块静态库：把 Buffer / UDP / tun / LinuxAdapter / core 全部编入
# ============================================================
add_library(vpn_modules STATIC
    Buffer/PacketBuffer.cpp
    Buffer/QueueBuffer.cpp
    UDP/UDP.cpp
    tun/tun.cpp
    LinuxAdapter/LinuxAdapter.cpp
    core/VpnCore.cpp
    Crypt/crypt.cpp
)

# 暴露所有头文件目录，方便各模块用 "PacketBuffer.h" 等直接包含
target_include_directories(vpn_modules PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/Buffer
    ${CMAKE_CURRENT_SOURCE_DIR}/UDP
    ${CMAKE_CURRENT_SOURCE_DIR}/tun
    ${CMAKE_CURRENT_SOURCE_DIR}/LinuxAdapter
    ${CMAKE_CURRENT_SOURCE_DIR}/core
    ${CMAKE_CURRENT_SOURCE_DIR}/Crypt
)

# 线程（std::thread / std::mutex 需要链接 pthread）
find_package(Threads REQUIRED)
# 加密（X25519 / HKDF / AES-256-GCM）
find_package(OpenSSL REQUIRED)
target_link_libraries(vpn_modules PUBLIC Threads::Threads OpenSSL::Crypto)

# 编译告警
target_compile_options(vpn_modules PRIVATE -Wall -Wextra)

# ============================================================
# 2) 可执行文件 vpn_server（服务端入口）
# ============================================================
add_executable(vpn_server
    main.cpp
)
target_link_libraries(vpn_server PRIVATE vpn_modules)
