// src/receiver/NetlinkReceiver.hpp
#pragma once
#include <functional>
#include <string>
#include <atomic>

struct AuditRawEvent {
    int            type;
    uint64_t       serial;
    double         timestamp;
    std::string    data;
};

class NetlinkReceiver {
public:
    using RawEventCb = std::function<void(const AuditRawEvent&)>;

    explicit NetlinkReceiver(RawEventCb cb);
    ~NetlinkReceiver() = default;

    bool start();
    void stop();

private:
    void runDispatcher();
    bool parseLine(const std::string& line, AuditRawEvent& ev);

    RawEventCb         m_cb;
    std::atomic<bool>  m_running{false};
};
