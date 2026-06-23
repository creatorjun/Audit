// src/parser/EventParser.hpp
#pragma once
#include "../model/AuditRecord.hpp"
#include "../receiver/NetlinkReceiver.hpp"
#include <functional>
#include <unordered_map>
#include <string>
#include <chrono>

struct PartialRecord {
    AuditRecord                             record;
    bool                                    hasSyscall;
    bool                                    hasExecve;
    bool                                    hasCwd;
    std::chrono::steady_clock::time_point   createdAt;
};

using RecordCallback = std::function<void(const AuditRecord&)>;

class EventParser {
public:
    explicit EventParser(RecordCallback cb);

    void onRawEvent(const AuditRawEvent& ev);
    void flushExpired();

private:
    void parseSyscall(PartialRecord& pr, const std::string& data);
    void parseExecve(PartialRecord& pr,  const std::string& data);
    void parseCwd(PartialRecord& pr,     const std::string& data);
    void parsePath(PartialRecord& pr,    const std::string& data);

    std::string extractField(const std::string& data, const std::string& key);
    std::string extractFieldExact(const std::string& data, const std::string& key);
    std::string decodeHexOrQuoted(const std::string& val);
    uid_t       resolveUid(const std::string& s);
    std::string uidToName(uid_t uid);

    RecordCallback                              m_callback;
    std::unordered_map<uint64_t, PartialRecord> m_pending;
    static constexpr int                        TTL_SECONDS = 5;
};
