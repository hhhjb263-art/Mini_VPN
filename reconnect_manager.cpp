#include "reconnect_manager.h"

#include <algorithm>
#include <chrono>
#include <exception>
#include <utility>

#include "common/tun_macro.h"

namespace
{
    // 单次连接：等待握手完成的上限（UDP 内部握手超时约 5s）
    constexpr auto kHandshakeWait = std::chrono::seconds(8);
    // 重连退避：500ms -> 1s -> 2s -> 5s（封顶）
    constexpr auto kMinBackoff = std::chrono::milliseconds(500);
    constexpr auto kMaxBackoff = std::chrono::milliseconds(5000);
    // 连接监视周期
    constexpr auto kMonitorTick = std::chrono::milliseconds(50);
}

ReconnectManager::ReconnectManager(std::string remoteIp, uint16_t port, size_t queueMax)
    : m_remote(std::move(remoteIp))
    , m_port(port)
    , m_queueMax(queueMax)
{
}

ReconnectManager::~ReconnectManager()
{
    stop();
}

bool ReconnectManager::start()
{
    if (m_running.load())
    {
        LOG_WARN("[Reconnect] 已在运行");
        return false;
    }
    m_running.store(true);
    set_state(ConnState::Connecting);
    m_worker = std::thread(&ReconnectManager::worker_loop, this);
    return true;
}

void ReconnectManager::stop()
{
    m_running.store(false);
    if (m_worker.joinable())
    {
        m_worker.join();
    }
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        teardown_current_locked();
    }
    set_state(ConnState::Stopped);
}

std::shared_ptr<UDP> ReconnectManager::udp() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_current;
}

void ReconnectManager::set_state_callback(StateCallback cb)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_onState = std::move(cb);
}

void ReconnectManager::set_connected_callback(ConnectedCallback cb)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_onConnected = std::move(cb);
}

void ReconnectManager::force_disconnect_for_test()
{
    m_forceBreak.store(true);
}

const char* ReconnectManager::state_name(ConnState s)
{
    switch (s)
    {
    case ConnState::Stopped:      return "Stopped";
    case ConnState::Connecting:   return "Connecting";
    case ConnState::Connected:    return "Connected";
    case ConnState::Reconnecting: return "Reconnecting";
    case ConnState::Error:        return "Error";
    default:                      return "Unknown";
    }
}

void ReconnectManager::worker_loop()
{
    auto backoff = kMinBackoff;
    bool firstAttempt = true;

    while (m_running.load())
    {
        set_state(firstAttempt ? ConnState::Connecting : ConnState::Reconnecting);
        firstAttempt = false;

        // ---------- 1) 建立连接 ----------
        if (!connect_once())
        {
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                teardown_current_locked();
            }
            if (!m_running.load())
            {
                break;
            }
            // 退避后重试
            set_state(ConnState::Reconnecting);
            std::this_thread::sleep_for(backoff);
            backoff = (std::min)(backoff * 2, kMaxBackoff);
            continue;
        }
        backoff = kMinBackoff;
        set_state(ConnState::Connected);
        if (m_onConnected)
        {
            m_onConnected();
        }

        // ---------- 2) 监视连接 ----------
        while (m_running.load())
        {
            if (m_forceBreak.exchange(false))
            {
                LOG_WARN("[Reconnect] 收到测试断线指令");
                break;
            }
            auto u = udp();
            if (!u)
            {
                break;
            }
            if (!u->is_handshaked() || u->needs_reconnect())
            {
                LOG_WARN("[Reconnect] 连接已断开（need_reconnect / 握手丢失）");
                break;
            }
            std::this_thread::sleep_for(kMonitorTick);
        }
        if (!m_running.load())
        {
            break;
        }

        // ---------- 3) 断开：销毁旧实例，进入重连 ----------
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            teardown_current_locked();
        }
        set_state(ConnState::Reconnecting);
    }

    {
        std::lock_guard<std::mutex> lock(m_mutex);
        teardown_current_locked();
    }
    set_state(ConnState::Stopped);
}

bool ReconnectManager::connect_once()
{
    std::shared_ptr<UDP> u;
    try
    {
        u = std::make_shared<UDP>(m_remote.c_str(), m_port, false, m_queueMax);
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("[Reconnect] 参数错误（%s），状态机停止", e.what());
        set_state(ConnState::Error);
        m_running.store(false);
        return false;
    }

    if (!u->init())
    {
        LOG_ERROR("[Reconnect] UDP init 失败 remote=%s:%u", m_remote.c_str(), m_port);
        return false;
    }
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_current = u;
    }
    LOG_INFO("[Reconnect] 已创建隧道，等待握手 remote=%s:%u ...", m_remote.c_str(), m_port);

    const auto deadline = std::chrono::steady_clock::now() + kHandshakeWait;
    while (m_running.load())
    {
        if (u->is_handshaked())
        {
            LOG_INFO("[Reconnect] 握手成功，连接建立");
            return true;
        }
        if (u->needs_reconnect())
        {
            LOG_WARN("[Reconnect] 握手失败/对端不可达");
            return false;
        }
        if (std::chrono::steady_clock::now() >= deadline)
        {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    LOG_WARN("[Reconnect] 握手等待超时");
    return u->is_handshaked();
}

void ReconnectManager::teardown_current_locked()
{
    if (m_current)
    {
        m_current->stop();
        m_current.reset();
    }
}

void ReconnectManager::set_state(ConnState s)
{
    m_state.store(s);
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_onState)
    {
        m_onState(s);
    }
}