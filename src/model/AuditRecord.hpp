// src/model/AuditRecord.hpp
#pragma once
#include <string>
#include <ctime>
#include <sys/types.h>

struct AuditRecord {
    uint64_t    serial;
    timespec    timestamp;
    pid_t       pid;
    pid_t       ppid;
    uid_t       uid;
    uid_t       auid;
    gid_t       gid;
    std::string comm;
    std::string exe;
    std::string cmdline;
    std::string cwd;
    std::string tty;
    std::string hostname;
    int         exit_code;
    bool        success;
};
