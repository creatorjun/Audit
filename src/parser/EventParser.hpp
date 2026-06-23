// src/parser/EventParser.hpp
#pragma once
#include "../model/AuditRecord.hpp"
#include "../receiver/NetlinkReceiver.hpp"
#include <functional>
#include <unordered_map>
#include <map>
#include <string>
#include <chrono>

struct PartialRecord {
    AuditRecord                             record;
    bool                                    hasSyscall;
    bool                                    hasExecve;
    bool                                    hasCwd;
    std::chrono::steady_clock::time_point   expiresAt;
};

using RecordCallback = std::function<void(const AuditRecord&)>;

class EventParser {
public:
    explicit EventParser(RecordCallback cb);

    void onRawEvent(const AuditRawEvent& ev);

private:
    void flushExpired();
    void parseSyscall(PartialRecord& pr, const AuditRawEvent& ev);
    void parseExecve(PartialRecord& pr,  const std::string& data);
    void parseCwd(PartialRecord& pr,     const std::string& data);
    void parsePath(PartialRecord& pr,    const std::string& data);

    std::string extractFieldExact(const std::string& data, const std::string& key);
    std::string decodeHexOrQuoted(const std::string& val);
    uid_t       resolveUid(const std::string& s);

    RecordCallback                              m_callback;
    std::unordered_map<uint64_t, PartialRecord> m_pending;
    std::multimap<std::chrono::steady_clock::time_point, uint64_t> m_expiry;

    static constexpr int TTL_SECONDS      = 5;
    static constexpr int FLUSH_INTERVAL_S = 2;

    std::chrono::steady_clock::time_point   m_lastFlush;
};
