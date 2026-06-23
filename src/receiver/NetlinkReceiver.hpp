// src/receiver/NetlinkReceiver.hpp
#pragma once
#include <functional>
#include <string>
#include <atomic>

struct AuditRawEvent {
    int         type;
    uint64_t    serial;
    std::string data;
};

using RawEventCallback = std::function<void(const AuditRawEvent&)>;

class NetlinkReceiver {
public:
    explicit NetlinkReceiver(RawEventCallback cb);
    ~NetlinkReceiver();

    bool start();
    void stop();

private:
    void run();
    bool setupAuditRules();
    void cleanupAuditRules();

    RawEventCallback    m_callback;
    int                 m_auditFd;
    int                 m_epollFd;
    std::atomic<bool>   m_running;
};
