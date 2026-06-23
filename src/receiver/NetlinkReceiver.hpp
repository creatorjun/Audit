// src/receiver/NetlinkReceiver.hpp
#pragma once
#include <functional>
#include <string>
#include <atomic>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <ctime>

enum class ReceiverMode {
    Standalone,
    Dispatcher
};

struct AuditRawEvent {
    int         type;
    uint64_t    serial;
    timespec    timestamp;
    std::string data;
};

using RawEventCallback = std::function<void(const AuditRawEvent&)>;

class NetlinkReceiver {
public:
    NetlinkReceiver(RawEventCallback cb, ReceiverMode mode, size_t maxQueue = 16384);
    ~NetlinkReceiver();

    bool start();
    void stop();

private:
    void runStandalone();
    void runDispatcher();
    void dispatchLoop();

    bool setupAuditRules();
    void cleanupAuditRules();

    bool parseLine(const std::string& line, AuditRawEvent& ev);

    RawEventCallback            m_callback;
    ReceiverMode                m_mode;
    int                         m_auditFd;
    int                         m_epollFd;
    std::atomic<bool>           m_running;
    size_t                      m_maxQueue;

    std::thread                 m_ioThread;
    std::thread                 m_dispatchThread;
    std::mutex                  m_queueMutex;
    std::condition_variable     m_queueCv;
    std::queue<AuditRawEvent>   m_rawQueue;
};
