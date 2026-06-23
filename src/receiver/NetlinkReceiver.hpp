// src/receiver/NetlinkReceiver.hpp
#pragma once
#include <functional>
#include <string>
#include <atomic>

enum class ReceiverMode {
    Standalone,
    Dispatcher
};

struct AuditRawEvent {
    int         type;
    uint64_t    serial;
    std::string data;
};

using RawEventCallback = std::function<void(const AuditRawEvent&)>;

class NetlinkReceiver {
public:
    NetlinkReceiver(RawEventCallback cb, ReceiverMode mode);
    ~NetlinkReceiver();

    bool start();
    void stop();

private:
    void runStandalone();
    void runDispatcher();

    bool setupAuditRules();
    void cleanupAuditRules();

    bool parseLine(const std::string& line, AuditRawEvent& ev);

    RawEventCallback    m_callback;
    ReceiverMode        m_mode;
    int                 m_auditFd;
    int                 m_epollFd;
    std::atomic<bool>   m_running;
};
