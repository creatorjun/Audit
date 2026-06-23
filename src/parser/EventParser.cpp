// src/parser/EventParser.cpp
#include "EventParser.hpp"
#include <libaudit.h>
#include <syslog.h>
#include <pwd.h>
#include <cstring>
#include <sstream>
#include <iomanip>

EventParser::EventParser(RecordCallback cb)
    : m_callback(std::move(cb))
{}

void EventParser::onRawEvent(const AuditRawEvent& ev) {
    flushExpired();

    if (ev.type == AUDIT_EOE) {
        auto it = m_pending.find(ev.serial);
        if (it != m_pending.end() && it->second.hasSyscall) {
            m_callback(it->second.record);
        }
        m_pending.erase(ev.serial);
        return;
    }

    auto& pr = m_pending[ev.serial];
    if (pr.record.serial == 0) {
        pr.record.serial  = ev.serial;
        pr.hasSyscall     = false;
        pr.hasExecve      = false;
        pr.hasCwd         = false;
        pr.createdAt      = std::chrono::steady_clock::now();
    }

    switch (ev.type) {
        case AUDIT_SYSCALL: parseSyscall(pr, ev.data); break;
        case AUDIT_EXECVE:  parseExecve(pr,  ev.data); break;
        case AUDIT_CWD:     parseCwd(pr,     ev.data); break;
        case AUDIT_PATH:    parsePath(pr,    ev.data); break;
        default: break;
    }
}

void EventParser::flushExpired() {
    auto now = std::chrono::steady_clock::now();
    for (auto it = m_pending.begin(); it != m_pending.end(); ) {
        auto age = std::chrono::duration_cast<std::chrono::seconds>(
            now - it->second.createdAt).count();
        if (age > TTL_SECONDS) {
            it = m_pending.erase(it);
        } else {
            ++it;
        }
    }
}

void EventParser::parseSyscall(PartialRecord& pr, const std::string& data) {
    pr.hasSyscall = true;
    auto& r = pr.record;

    std::string pidStr  = extractField(data, "pid");
    std::string ppidStr = extractField(data, "ppid");
    std::string uidStr  = extractField(data, "uid");
    std::string auidStr = extractField(data, "auid");
    std::string gidStr  = extractField(data, "gid");
    std::string comm    = extractField(data, "comm");
    std::string exe     = extractField(data, "exe");
    std::string tty     = extractField(data, "tty");
    std::string host    = extractField(data, "hostname");
    std::string suc     = extractField(data, "success");

    if (!pidStr.empty())  r.pid      = static_cast<pid_t>(std::stol(pidStr));
    if (!ppidStr.empty()) r.ppid     = static_cast<pid_t>(std::stol(ppidStr));
    if (!uidStr.empty())  r.uid      = resolveUid(uidStr);
    if (!auidStr.empty()) r.auid     = resolveUid(auidStr);
    if (!gidStr.empty())  r.gid      = static_cast<gid_t>(std::stol(gidStr));
    if (!comm.empty())    r.comm     = decodeHexOrQuoted(comm);
    if (!exe.empty())     r.exe      = decodeHexOrQuoted(exe);
    if (!tty.empty())     r.tty      = tty;
    if (!host.empty())    r.hostname = host;
    r.success = (suc == "yes");

    std::string tsStr = extractField(data, "msg=audit(");
    if (!tsStr.empty()) {
        double ts = std::stod(tsStr);
        r.timestamp.tv_sec  = static_cast<time_t>(ts);
        r.timestamp.tv_nsec = static_cast<long>((ts - r.timestamp.tv_sec) * 1e9);
    }
}

void EventParser::parseExecve(PartialRecord& pr, const std::string& data) {
    pr.hasExecve = true;
    std::string argc_str = extractField(data, "argc");
    if (argc_str.empty()) return;

    int argc = std::stoi(argc_str);
    std::ostringstream oss;
    for (int i = 0; i < argc; ++i) {
        std::string key = "a" + std::to_string(i);
        std::string val = extractField(data, key);
        if (!val.empty()) {
            if (i > 0) oss << ' ';
            oss << decodeHexOrQuoted(val);
        }
    }
    pr.record.cmdline = oss.str();
}

void EventParser::parseCwd(PartialRecord& pr, const std::string& data) {
    pr.hasCwd = true;
    std::string cwd = extractField(data, "cwd");
    if (!cwd.empty()) pr.record.cwd = decodeHexOrQuoted(cwd);
}

void EventParser::parsePath(PartialRecord& pr, const std::string& data) {
    std::string name = extractField(data, "name");
    if (!name.empty() && pr.record.exe.empty()) {
        pr.record.exe = decodeHexOrQuoted(name);
    }
}

std::string EventParser::extractField(const std::string& data, const std::string& key) {
    std::string search = key + "=";
    auto pos = data.find(search);
    if (pos == std::string::npos) return {};
    pos += search.size();

    if (pos >= data.size()) return {};

    if (data[pos] == '"') {
        ++pos;
        auto end = data.find('"', pos);
        if (end == std::string::npos) return {};
        return data.substr(pos, end - pos);
    }

    auto end = data.find(' ', pos);
    if (end == std::string::npos) end = data.size();
    return data.substr(pos, end - pos);
}

std::string EventParser::decodeHexOrQuoted(const std::string& val) {
    if (val.empty()) return val;
    if (val.front() == '"' && val.back() == '"') {
        return val.substr(1, val.size() - 2);
    }
    if (val.size() % 2 == 0) {
        bool isHex = true;
        for (char c : val) {
            if (!std::isxdigit(static_cast<unsigned char>(c))) { isHex = false; break; }
        }
        if (isHex) {
            std::string out;
            out.reserve(val.size() / 2);
            for (size_t i = 0; i < val.size(); i += 2) {
                out += static_cast<char>(std::stoi(val.substr(i, 2), nullptr, 16));
            }
            return out;
        }
    }
    return val;
}

uid_t EventParser::resolveUid(const std::string& s) {
    if (s == "unset" || s == "4294967295") return static_cast<uid_t>(-1);
    try { return static_cast<uid_t>(std::stoul(s)); }
    catch (...) { return static_cast<uid_t>(-1); }
}

std::string EventParser::uidToName(uid_t uid) {
    if (uid == static_cast<uid_t>(-1)) return "unset";
    struct passwd* pw = getpwuid(uid);
    return pw ? std::string(pw->pw_name) : std::to_string(uid);
}
