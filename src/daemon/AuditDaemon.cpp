// src/daemon/AuditDaemon.cpp
#include "AuditDaemon.hpp"
#include "../writer/LogWriter.hpp"
#include "../parser/EventParser.hpp"
#include "../receiver/NetlinkReceiver.hpp"
#include <syslog.h>
#include <fstream>
#include <sstream>
#include <signal.h>
#include <unistd.h>
#include <cstring>
#include <chrono>
#include <thread>

static AuditDaemon* g_daemon = nullptr;

static void sigHandler(int) {
    if (g_daemon) g_daemon->requestStop();
}

AuditDaemon::AuditDaemon(DaemonConfig cfg)
    : m_cfg(std::move(cfg))
{}

AuditDaemon::~AuditDaemon() {
    removePid();
}

void AuditDaemon::requestStop() {
    m_running = false;
    if (m_receiver) m_receiver->stop();
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
        if      (key == "log_dir")                   cfg.logDir                  = val;
        else if (key == "log_retention_days")        cfg.retentionDays           = std::stoi(val);
        else if (key == "pid_file")                  cfg.pidFile                 = val;
        else if (key == "filter_system_daemons")     cfg.filterDaemons           = (val == "true");
        else if (key == "queue_max_size")            cfg.queueMaxSize            = std::stoull(val);
        else if (key == "resource_log_interval_sec") cfg.resourceLogIntervalSec = std::stoi(val);
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
        m_cfg.mode,
        m_cfg.queueMaxSize
    );

    m_running = true;
    g_daemon  = this;

    struct sigaction sa{};
    sa.sa_handler = sigHandler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGTERM, &sa, nullptr);
    sigaction(SIGINT,  &sa, nullptr);
    signal(SIGHUP, SIG_IGN);

    m_resourceThread = std::thread(&AuditDaemon::resourceMonitorLoop, this);

    if (!m_receiver->start()) {
        syslog(LOG_ERR, "audit-daemon: receiver failed to start");
        m_running = false;
        m_resourceThread.join();
        g_daemon = nullptr;
        m_writer->stop();
        return;
    }

    m_running = false;
    if (m_resourceThread.joinable()) m_resourceThread.join();
    g_daemon = nullptr;
    syslog(LOG_INFO, "audit-daemon stopped");
    m_writer->stop();
}

void AuditDaemon::resourceMonitorLoop() {
    const auto interval = std::chrono::seconds(m_cfg.resourceLogIntervalSec);
    auto nextTick = std::chrono::steady_clock::now() + interval;

    while (m_running) {
        auto now = std::chrono::steady_clock::now();
        if (now >= nextTick) {
            ResourceSnapshot snap{};
            if (collectResource(snap)) {
                syslog(LOG_INFO,
                       "audit-daemon resource: cpu=%.2f%% rss=%ldKB vsz=%ldKB",
                       snap.cpuPercent, snap.rssKb, snap.vmRssKb);
            }
            nextTick = std::chrono::steady_clock::now() + interval;
        }
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

bool AuditDaemon::collectResource(ResourceSnapshot& snap) {
    pid_t pid = getpid();

    std::string statusPath = "/proc/" + std::to_string(pid) + "/status";
    std::ifstream statusFile(statusPath);
    if (!statusFile.is_open()) return false;

    snap.rssKb   = 0;
    snap.vmRssKb = 0;
    std::string line;
    while (std::getline(statusFile, line)) {
        if (line.rfind("VmRSS:", 0) == 0) {
            std::istringstream iss(line.substr(6));
            iss >> snap.rssKb;
            snap.vmRssKb = snap.rssKb;
        } else if (line.rfind("VmSize:", 0) == 0) {
            std::istringstream iss(line.substr(7));
            long vsz = 0;
            iss >> vsz;
            snap.vmRssKb = vsz;
        }
    }

    std::string statPath1 = "/proc/" + std::to_string(pid) + "/stat";
    auto readStat = [&](unsigned long long& utime, unsigned long long& stime) -> bool {
        std::ifstream sf(statPath1);
        if (!sf.is_open()) return false;
        std::string s;
        std::getline(sf, s);
        auto rp = s.rfind(')');
        if (rp == std::string::npos) return false;
        std::istringstream iss(s.substr(rp + 2));
        std::string tok;
        for (int i = 3; i <= 13; ++i) {
            if (!(iss >> tok)) return false;
            if (i == 13) utime = std::stoull(tok);
        }
        if (!(iss >> tok)) return false;
        stime = std::stoull(tok);
        return true;
    };

    std::string uptimePath = "/proc/uptime";
    auto readUptime = [&](double& uptime) -> bool {
        std::ifstream uf(uptimePath);
        if (!uf.is_open()) return false;
        return static_cast<bool>(uf >> uptime);
    };

    unsigned long long utime1 = 0, stime1 = 0;
    unsigned long long utime2 = 0, stime2 = 0;
    double uptime1 = 0, uptime2 = 0;

    if (!readStat(utime1, stime1) || !readUptime(uptime1)) {
        snap.cpuPercent = 0.0;
        return true;
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    if (!readStat(utime2, stime2) || !readUptime(uptime2)) {
        snap.cpuPercent = 0.0;
        return true;
    }

    long clkTck = sysconf(_SC_CLK_TCK);
    if (clkTck <= 0) clkTck = 100;

    double deltaProc   = static_cast<double>((utime2 + stime2) - (utime1 + stime1)) / clkTck;
    double deltaWall   = uptime2 - uptime1;
    snap.cpuPercent    = (deltaWall > 0.0) ? (deltaProc / deltaWall * 100.0) : 0.0;

    return true;
}

void AuditDaemon::writePid() {
    std::ofstream f(m_cfg.pidFile);
    if (f.is_open()) f << getpid() << "\n";
}

void AuditDaemon::removePid() {
    unlink(m_cfg.pidFile.c_str());
}
