// src/daemon/AuditDaemon.hpp
#pragma once
#include <string>
#include <memory>
#include <thread>
#include <atomic>

class EventParser;
class LogWriter;
class NetlinkReceiver;

struct DaemonConfig {
    std::string  logDir          = "/var/log/audit-daemon";
    std::string  pidFile         = "/var/run/audit-daemon.pid";
    int          retentionDays   = 90;
    bool         filterDaemons   = true;
    size_t       queueMaxSize    = 8192;
    int          resourceLogIntervalSec = 600;
};

class AuditDaemon {
public:
    explicit AuditDaemon(DaemonConfig cfg);
    ~AuditDaemon();

    static bool loadConfig(const std::string& path, DaemonConfig& cfg);
    void run();
    void requestStop();

private:
    void writePid();
    void removePid();
    void resourceMonitorLoop();

    struct ResourceSnapshot {
        double cpuPercent;
        long   rssKb;
        long   vmRssKb;
    };
    bool collectResource(ResourceSnapshot& snap);

    DaemonConfig                     m_cfg;
    std::unique_ptr<LogWriter>       m_writer;
    std::unique_ptr<EventParser>     m_parser;
    std::unique_ptr<NetlinkReceiver> m_receiver;
    std::thread                      m_resourceThread;
    std::atomic<bool>                m_running{false};
};
