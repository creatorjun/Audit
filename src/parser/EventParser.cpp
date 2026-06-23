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

    // Bug fix 1: pid= 보다 ppid= 를 먼저 추출해야 pid= 검색이 ppid= 에 오매칭되지 않음
    std::string ppidStr = extractFieldExact(data, "ppid");
    std::string pidStr  = extractFieldExact(data, "pid");
    std::string uidStr  = extractFieldExact(data, "uid");
    std::string auidStr = extractFieldExact(data, "auid");
    std::string gidStr  = extractFieldExact(data, "gid");
    std::string comm    = extractFieldExact(data, "comm");
    std::string exe     = extractFieldExact(data, "exe");
    std::string tty     = extractFieldExact(data, "tty");
    std::string host    = extractFieldExact(data, "hostname");
    std::string suc     = extractFieldExact(data, "success");

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

    // Bug fix 2: msg=audit(timestamp:serial) 파싱
    // 형식: msg=audit(1719100800.123:456):
    auto msgPos = data.find("msg=audit(");
    if (msgPos != std::string::npos) {
        auto tsStart  = msgPos + 10;
        auto colonPos = data.find(':', tsStart);
        if (colonPos != std::string::npos) {
            try {
                double ts = std::stod(data.substr(tsStart, colonPos - tsStart));
                r.timestamp.tv_sec  = static_cast<time_t>(ts);
                r.timestamp.tv_nsec = static_cast<long>((ts - static_cast<double>(r.timestamp.tv_sec)) * 1e9);
            } catch (...) {}
        }
    }
}

void EventParser::parseExecve(PartialRecord& pr, const std::string& data) {
    pr.hasExecve = true;
    std::string argc_str = extractFieldExact(data, "argc");
    if (argc_str.empty()) return;

    int argc = 0;
    try { argc = std::stoi(argc_str); } catch (...) { return; }

    std::ostringstream oss;
    for (int i = 0; i < argc; ++i) {
        std::string key = "a" + std::to_string(i);
        std::string val = extractFieldExact(data, key);
        if (!val.empty()) {
            if (i > 0) oss << ' ';
            oss << decodeHexOrQuoted(val);
        }
    }
    pr.record.cmdline = oss.str();
}

void EventParser::parseCwd(PartialRecord& pr, const std::string& data) {
    pr.hasCwd = true;
    std::string cwd = extractFieldExact(data, "cwd");
    if (!cwd.empty()) pr.record.cwd = decodeHexOrQuoted(cwd);
}

void EventParser::parsePath(PartialRecord& pr, const std::string& data) {
    std::string name = extractFieldExact(data, "name");
    if (!name.empty() && pr.record.exe.empty()) {
        pr.record.exe = decodeHexOrQuoted(name);
    }
}

// Bug fix 3: 단어 경계 기반 정확한 필드 추출 (pid= 가 ppid= 에 오매칭되는 문제 방지)
std::string EventParser::extractFieldExact(const std::string& data, const std::string& key) {
    std::string search = key + "=";
    size_t pos = 0;
    while (pos < data.size()) {
        auto found = data.find(search, pos);
        if (found == std::string::npos) break;

        // 앞 문자가 공백, 시작, 또는 '(' 여야 단어 경계로 판단
        bool validPrefix = (found == 0) ||
                           (data[found - 1] == ' ') ||
                           (data[found - 1] == '(');
        if (!validPrefix) {
            pos = found + search.size();
            continue;
        }

        size_t valStart = found + search.size();
        if (valStart >= data.size()) return {};

        if (data[valStart] == '"') {
            ++valStart;
            auto end = data.find('"', valStart);
            if (end == std::string::npos) return {};
            return data.substr(valStart, end - valStart);
        }

        auto end = data.find(' ', valStart);
        if (end == std::string::npos) end = data.size();
        return data.substr(valStart, end - valStart);
    }
    return {};
}

std::string EventParser::extractField(const std::string& data, const std::string& key) {
    return extractFieldExact(data, key);
}

// Bug fix 4: hex 디코딩 후 non-printable 바이트를 '?' 로 치환하여 JSON 깨짐 방지
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
                unsigned char byte = static_cast<unsigned char>(
                    std::stoi(val.substr(i, 2), nullptr, 16));
                // non-printable ASCII 는 '?' 로 치환
                if (byte < 0x20 || byte == 0x7F) {
                    out += '?';
                } else {
                    out += static_cast<char>(byte);
                }
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
