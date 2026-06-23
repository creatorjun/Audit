// src/writer/LogWriter.cpp
#include "LogWriter.hpp"
#include <syslog.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <pwd.h>
#include <ctime>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <stdexcept>

LogWriter::LogWriter(const std::string& logDir, int retentionDays, size_t maxQueue)
    : m_logDir(logDir)
    , m_retentionDays(retentionDays)
    , m_maxQueue(maxQueue)
    , m_fd(-1)
    , m_running(true)
{
    mkdir(m_logDir.c_str(), 0750);
    rotateIfNeeded();
    m_thread = std::thread(&LogWriter::run, this);
}

LogWriter::~LogWriter() {
    stop();
}

void LogWriter::stop() {
    m_running = false;
    m_cv.notify_all();
    if (m_thread.joinable()) m_thread.join();
    if (m_fd >= 0) { close(m_fd); m_fd = -1; }
}

void LogWriter::enqueue(const AuditRecord& record) {
    std::unique_lock<std::mutex> lock(m_mutex);
    if (m_queue.size() >= m_maxQueue) {
        syslog(LOG_WARNING, "LogWriter queue full, dropping record");
        return;
    }
    m_queue.push(record);
    m_cv.notify_one();
}

void LogWriter::enqueue(AuditRecord&& record) {
    std::unique_lock<std::mutex> lock(m_mutex);
    if (m_queue.size() >= m_maxQueue) {
        syslog(LOG_WARNING, "LogWriter queue full, dropping record");
        return;
    }
    m_queue.push(std::move(record));
    m_cv.notify_one();
}

void LogWriter::run() {
    while (m_running || !m_queue.empty()) {
        std::unique_lock<std::mutex> lock(m_mutex);
        m_cv.wait(lock, [this]{ return !m_queue.empty() || !m_running; });

        while (!m_queue.empty()) {
            AuditRecord rec = std::move(m_queue.front());
            m_queue.pop();
            lock.unlock();
            rotateIfNeeded();
            writeRecord(rec);
            lock.lock();
        }
    }
}

void LogWriter::rotateIfNeeded() {
    std::string today = currentDateStr();
    if (today == m_currentDate && m_fd >= 0) return;

    if (m_fd >= 0) { close(m_fd); m_fd = -1; }
    m_currentDate = today;
    m_currentPath = m_logDir + "/" + today + ".log";

    m_fd = open(m_currentPath.c_str(),
                O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0640);
    if (m_fd < 0) {
        syslog(LOG_ERR, "LogWriter: failed to open %s: %s",
               m_currentPath.c_str(), strerror(errno));
    }
    purgeOldLogs();
}

void LogWriter::writeRecord(const AuditRecord& record) {
    if (m_fd < 0) return;
    std::string line = buildJson(record) + "\n";
    ssize_t written = write(m_fd, line.c_str(), line.size());
    if (written < 0) {
        syslog(LOG_ERR, "LogWriter write failed: %s", strerror(errno));
    }
}

void LogWriter::purgeOldLogs() {
    DIR* dir = opendir(m_logDir.c_str());
    if (!dir) return;

    struct dirent* ent;
    while ((ent = readdir(dir)) != nullptr) {
        std::string name(ent->d_name);
        if (name.size() != 14 || name.substr(10) != ".log") continue;

        struct tm tm_info{};
        if (strptime(name.substr(0, 10).c_str(), "%Y-%m-%d", &tm_info) == nullptr) continue;
        tm_info.tm_hour = 0; tm_info.tm_min = 0; tm_info.tm_sec = 0; tm_info.tm_isdst = -1;
        time_t fileDate = mktime(&tm_info);
        if (fileDate == static_cast<time_t>(-1)) continue;

        time_t cutoff = time(nullptr) - static_cast<time_t>(m_retentionDays) * 86400;
        if (fileDate < cutoff) {
            std::string path = m_logDir + "/" + name;
            unlink(path.c_str());
        }
    }
    closedir(dir);
}

const std::string& LogWriter::cachedUidName(uid_t uid) {
    static const std::string kUnset = "unset";
    if (uid == static_cast<uid_t>(-1)) return kUnset;

    auto now = std::chrono::steady_clock::now();
    auto it  = m_uidCache.find(uid);
    if (it != m_uidCache.end() && it->second.expiresAt > now) {
        return it->second.name;
    }

    struct passwd* pw = getpwuid(uid);
    std::string name  = pw ? std::string(pw->pw_name) : std::to_string(uid);
    m_uidCache[uid]   = { name, now + std::chrono::seconds(UID_CACHE_TTL_S) };
    return m_uidCache[uid].name;
}

std::string LogWriter::buildJson(const AuditRecord& r) {
    auto escapeJson = [](const std::string& s) -> std::string {
        std::ostringstream oss;
        for (unsigned char c : s) {
            if      (c == '"')  oss << "\\\"";
            else if (c == '\\') oss << "\\\\";
            else if (c < 0x20)  oss << "\\u" << std::hex << std::setw(4) << std::setfill('0') << (int)c;
            else                oss << c;
        }
        return oss.str();
    };

    std::ostringstream j;
    j << "{";
    j << "\"ts\":\""        << formatTimestamp(r.timestamp) << "\",";
    j << "\"serial\":"      << r.serial              << ",";
    j << "\"pid\":"         << r.pid                 << ",";
    j << "\"ppid\":"        << r.ppid                << ",";
    j << "\"uid\":"         << r.uid                 << ",";
    j << "\"uid_name\":\""  << escapeJson(cachedUidName(r.uid))  << "\",";
    j << "\"auid\":"        << (r.auid == static_cast<uid_t>(-1) ? 4294967295u : (unsigned)r.auid) << ",";
    j << "\"auid_name\":\"" << escapeJson(cachedUidName(r.auid)) << "\",";
    j << "\"comm\":\""      << escapeJson(r.comm)    << "\",";
    j << "\"exe\":\""       << escapeJson(r.exe)     << "\",";
    j << "\"cmdline\":\""   << escapeJson(r.cmdline) << "\",";
    j << "\"cwd\":\""       << escapeJson(r.cwd)     << "\",";
    j << "\"tty\":\""       << escapeJson(r.tty)     << "\",";
    j << "\"hostname\":\""  << escapeJson(r.hostname) << "\",";
    j << "\"success\":"     << (r.success ? "true" : "false");
    j << "}";
    return j.str();
}

std::string LogWriter::currentDateStr() {
    time_t now = time(nullptr);
    struct tm tm_info{};
    localtime_r(&now, &tm_info);
    char buf[16];
    strftime(buf, sizeof(buf), "%Y-%m-%d", &tm_info);
    return buf;
}

std::string LogWriter::formatTimestamp(const timespec& ts) {
    struct tm tm_info{};
    localtime_r(&ts.tv_sec, &tm_info);
    char buf[64];
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &tm_info);
    char tz[8];
    strftime(tz, sizeof(tz), "%z", &tm_info);
    std::ostringstream oss;
    oss << buf << "." << std::setw(9) << std::setfill('0') << ts.tv_nsec << tz;
    return oss.str();
}
