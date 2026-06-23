// src/daemon/AuditDaemon.cpp
#include "AuditDaemon.hpp"
#include "../writer/LogWriter.hpp"
#include "../parser/EventParser.hpp"
#include "../receiver/NetlinkReceiver.hpp"
#include <syslog.h>
#include <fstream>
#include <signal.h>
#include <unistd.h>
#include <atomic>

static std::atomic<bool> g_stop{false};

AuditDaemon::AuditDaemon(DaemonConfig cfg)
    : m_cfg(std::move(cfg))
{}

AuditDaemon::~AuditDaemon() {
    removePid();
}

void AuditDaemon::requestStop() {
    g_stop = true;
}

bool AuditDaemon::loadConfig(const std::string& path, DaemonConfig& cfg) {
    std::ifstream f(path);
    if (!f.is_open()) return false;
    std::string line;
    while (std::getline(f, line)) {
        if (line.empty() || line[0] == '#') continue;
        auto pos = line.find('=');
        if (pos == std::string::npos) continue;
        std::string key = line.substr(0, pos);
        std::string val = line.substr(pos + 1);
        if      (key == "log_dir")               cfg.logDir        = val;
        else if (key == "log_retention_days")    cfg.retentionDays = std::stoi(val);
        else if (key == "pid_file")              cfg.pidFile       = val;
        else if (key == "filter_system_daemons") cfg.filterDaemons = (val == "true");
        else if (key == "queue_max_size")        cfg.queueMaxSize  = std::stoull(val);
        else if (key == "mode") {
            if (val == "standalone") cfg.mode = ReceiverMode::Standalone;
            else                     cfg.mode = ReceiverMode::Dispatcher;
        }
    }
    return true;
}

void AuditDaemon::run() {
    writePid();
    syslog(LOG_INFO, "audit-daemon started (pid=%d, mode=%s)",
           getpid(),
           m_cfg.mode == ReceiverMode::Dispatcher ? "dispatcher" : "standalone");

    m_writer = std::make_unique<LogWriter>(m_cfg.logDir, m_cfg.retentionDays, m_cfg.queueMaxSize);

    bool        filterDaemons = m_cfg.filterDaemons;
    LogWriter*  writerPtr     = m_writer.get();

    m_parser = std::make_unique<EventParser>([writerPtr, filterDaemons](const AuditRecord& rec) {
        if (filterDaemons && rec.auid == static_cast<uid_t>(-1)) return;
        writerPtr->enqueue(rec);
    });

    EventParser* parserPtr = m_parser.get();
    m_receiver = std::make_unique<NetlinkReceiver>(
        [parserPtr](const AuditRawEvent& ev) { parserPtr->onRawEvent(ev); },
        m_cfg.mode
    );

    m_receiver->start();

    syslog(LOG_INFO, "audit-daemon stopped");
    m_writer->stop();
}

void AuditDaemon::writePid() {
    std::ofstream f(m_cfg.pidFile);
    if (f.is_open()) f << getpid() << "\n";
}

void AuditDaemon::removePid() {
    unlink(m_cfg.pidFile.c_str());
}
