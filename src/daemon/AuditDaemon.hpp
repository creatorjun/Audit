// src/daemon/AuditDaemon.hpp
#pragma once
#include <string>
#include <memory>

class NetlinkReceiver;
class EventParser;
class LogWriter;

struct DaemonConfig {
    std::string logDir           = "/var/log/audit-daemon";
    std::string pidFile          = "/var/run/audit-daemon.pid";
    int         retentionDays    = 90;
    bool        filterDaemons    = true;
    size_t      queueMaxSize     = 8192;
};

class AuditDaemon {
public:
    explicit AuditDaemon(DaemonConfig cfg);
    ~AuditDaemon();

    static bool loadConfig(const std::string& path, DaemonConfig& cfg);
    void run();
    static void requestStop();

private:
    void writePid();
    void removePid();

    DaemonConfig                    m_cfg;
    std::unique_ptr<LogWriter>      m_writer;
    std::unique_ptr<EventParser>    m_parser;
    std::unique_ptr<NetlinkReceiver> m_receiver;
};
