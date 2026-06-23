// src/writer/LogWriter.hpp
#pragma once
#include "../model/AuditRecord.hpp"
#include <string>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <atomic>
#include <unordered_map>
#include <chrono>

class LogWriter {
public:
    explicit LogWriter(const std::string& logDir, int retentionDays = 90, size_t maxQueue = 8192);
    ~LogWriter();

    void enqueue(const AuditRecord& record);
    void enqueue(AuditRecord&& record);
    void stop();

private:
    void run();
    void writeRecord(const AuditRecord& record);
    void rotateIfNeeded();
    void purgeOldLogs();
    std::string buildJson(const AuditRecord& r);
    std::string currentDateStr();
    std::string formatTimestamp(const timespec& ts);
    const std::string& cachedUidName(uid_t uid);

    std::string                 m_logDir;
    int                         m_retentionDays;
    size_t                      m_maxQueue;
    std::string                 m_currentDate;
    std::string                 m_currentPath;
    int                         m_fd;

    std::thread                 m_thread;
    std::mutex                  m_mutex;
    std::condition_variable     m_cv;
    std::queue<AuditRecord>     m_queue;
    std::atomic<bool>           m_running;

    struct CacheEntry {
        std::string                             name;
        std::chrono::steady_clock::time_point   expiresAt;
    };
    std::unordered_map<uid_t, CacheEntry>   m_uidCache;
    static constexpr int UID_CACHE_TTL_S = 60;
};
