// src/receiver/NetlinkReceiver.cpp
#include "NetlinkReceiver.hpp"
#include <libaudit.h>
#include <linux/audit.h>
#include <linux/netlink.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <cstring>
#include <syslog.h>
#include <fcntl.h>

NetlinkReceiver::NetlinkReceiver(RawEventCallback cb, ReceiverMode mode)
    : m_callback(std::move(cb))
    , m_mode(mode)
    , m_auditFd(-1)
    , m_epollFd(-1)
    , m_running(false)
{}

NetlinkReceiver::~NetlinkReceiver() {
    stop();
}

bool NetlinkReceiver::start() {
    m_running = true;
    if (m_mode == ReceiverMode::Dispatcher) {
        runDispatcher();
    } else {
        m_auditFd = audit_open();
        if (m_auditFd < 0) {
            syslog(LOG_ERR, "audit_open failed: %s", strerror(errno));
            return false;
        }
        if (audit_set_pid(m_auditFd, getpid(), WAIT_YES) < 0) {
            syslog(LOG_ERR, "audit_set_pid failed: %s", strerror(errno));
            audit_close(m_auditFd);
            return false;
        }
        if (audit_set_enabled(m_auditFd, 1) < 0) {
            syslog(LOG_ERR, "audit_set_enabled failed");
            audit_close(m_auditFd);
            return false;
        }
        if (!setupAuditRules()) {
            audit_close(m_auditFd);
            return false;
        }
        m_epollFd = epoll_create1(EPOLL_CLOEXEC);
        if (m_epollFd < 0) {
            syslog(LOG_ERR, "epoll_create1 failed: %s", strerror(errno));
            cleanupAuditRules();
            audit_close(m_auditFd);
            return false;
        }
        epoll_event ev{};
        ev.events  = EPOLLIN;
        ev.data.fd = m_auditFd;
        if (epoll_ctl(m_epollFd, EPOLL_CTL_ADD, m_auditFd, &ev) < 0) {
            syslog(LOG_ERR, "epoll_ctl failed: %s", strerror(errno));
            close(m_epollFd);
            cleanupAuditRules();
            audit_close(m_auditFd);
            return false;
        }
        runStandalone();
    }
    return true;
}

void NetlinkReceiver::stop() {
    m_running = false;
    if (m_epollFd >= 0) { close(m_epollFd); m_epollFd = -1; }
    if (m_auditFd >= 0) {
        cleanupAuditRules();
        audit_set_pid(m_auditFd, 0, WAIT_NO);
        audit_close(m_auditFd);
        m_auditFd = -1;
    }
}

void NetlinkReceiver::runDispatcher() {
    syslog(LOG_INFO, "NetlinkReceiver: running in dispatcher mode (reading stdin)");

    int flags = fcntl(STDIN_FILENO, F_GETFL, 0);
    fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK);

    int epollFd = epoll_create1(EPOLL_CLOEXEC);
    if (epollFd < 0) {
        syslog(LOG_ERR, "epoll_create1 failed: %s", strerror(errno));
        return;
    }

    epoll_event ev{};
    ev.events  = EPOLLIN;
    ev.data.fd = STDIN_FILENO;
    epoll_ctl(epollFd, EPOLL_CTL_ADD, STDIN_FILENO, &ev);

    std::string lineBuf;
    char buf[4096];

    while (m_running) {
        epoll_event events[8];
        int n = epoll_wait(epollFd, events, 8, 1000);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        for (int i = 0; i < n; ++i) {
            if (!(events[i].events & EPOLLIN)) continue;
            ssize_t bytes;
            while ((bytes = read(STDIN_FILENO, buf, sizeof(buf))) > 0) {
                for (ssize_t j = 0; j < bytes; ++j) {
                    if (buf[j] == '\n') {
                        if (!lineBuf.empty()) {
                            AuditRawEvent rawEv;
                            if (parseLine(lineBuf, rawEv)) {
                                m_callback(rawEv);
                            }
                            lineBuf.clear();
                        }
                    } else {
                        lineBuf += buf[j];
                    }
                }
            }
            if (bytes == 0) {
                syslog(LOG_INFO, "NetlinkReceiver: stdin EOF, auditd closed pipe");
                m_running = false;
                break;
            }
        }
    }
    close(epollFd);
}

bool NetlinkReceiver::parseLine(const std::string& line, AuditRawEvent& ev) {
    auto typePos = line.find("type=");
    if (typePos == std::string::npos) return false;
    auto typeEnd = line.find(' ', typePos);
    if (typeEnd == std::string::npos) return false;
    std::string typeName = line.substr(typePos + 5, typeEnd - typePos - 5);

    if      (typeName == "SYSCALL") ev.type = AUDIT_SYSCALL;
    else if (typeName == "EXECVE")  ev.type = AUDIT_EXECVE;
    else if (typeName == "CWD")     ev.type = AUDIT_CWD;
    else if (typeName == "PATH")    ev.type = AUDIT_PATH;
    else if (typeName == "EOE")     ev.type = AUDIT_EOE;
    else return false;

    auto msgPos = line.find("msg=audit(");
    if (msgPos == std::string::npos) return false;
    auto colonPos = line.find(':', msgPos);
    auto parenPos = line.find(')', colonPos);
    if (colonPos == std::string::npos || parenPos == std::string::npos) return false;

    try {
        ev.serial = std::stoull(line.substr(colonPos + 1, parenPos - colonPos - 1));
    } catch (...) {
        return false;
    }

    auto dataStart = line.find(':', parenPos);
    if (dataStart != std::string::npos && dataStart + 2 <= line.size()) {
        ev.data = line.substr(dataStart + 2);
    }
    return true;
}

void NetlinkReceiver::runStandalone() {
    constexpr int MAX_EVENTS = 16;
    epoll_event events[MAX_EVENTS];

    while (m_running) {
        int n = epoll_wait(m_epollFd, events, MAX_EVENTS, 1000);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        for (int i = 0; i < n; ++i) {
            if (!(events[i].events & EPOLLIN)) continue;

            struct audit_reply reply;
            memset(&reply, 0, sizeof(reply));
            int rc = audit_get_reply(m_auditFd, &reply, GET_REPLY_NONBLOCKING, 0);
            if (rc <= 0) continue;

            if (reply.type != AUDIT_EOE    &&
                reply.type != AUDIT_SYSCALL &&
                reply.type != AUDIT_EXECVE  &&
                reply.type != AUDIT_CWD     &&
                reply.type != AUDIT_PATH) {
                continue;
            }

            AuditRawEvent ev;
            ev.type = reply.type;

            // serial은 netlink 헤더의 nlmsg_seq 필드에서 추출
            if (reply.nlh) {
                ev.serial = static_cast<uint64_t>(reply.nlh->nlmsg_seq);
            } else {
                ev.serial = 0;
            }

            if (reply.msg.data && reply.len > 0) {
                ev.data.assign(reply.msg.data, reply.len);
            }
            m_callback(ev);
        }
    }
}

bool NetlinkReceiver::setupAuditRules() {
    struct audit_rule_data* rule = audit_rule_create_data();
    if (!rule) return false;
    audit_rule_syscallbyname_data(rule, "execve");
    audit_rule_fieldpair_data(&rule, "arch=b64", AUDIT_FILTER_EXIT);
    rule->action = AUDIT_ALWAYS;
    rule->flags  = AUDIT_FILTER_EXIT;
    int rc = audit_add_rule_data(m_auditFd, rule, AUDIT_FILTER_EXIT, AUDIT_ALWAYS);
    audit_rule_free_data(rule);
    if (rc < 0) {
        rule = audit_rule_create_data();
        if (!rule) return false;
        audit_rule_syscallbyname_data(rule, "execve");
        audit_rule_fieldpair_data(&rule, "arch=b32", AUDIT_FILTER_EXIT);
        rule->action = AUDIT_ALWAYS;
        rule->flags  = AUDIT_FILTER_EXIT;
        rc = audit_add_rule_data(m_auditFd, rule, AUDIT_FILTER_EXIT, AUDIT_ALWAYS);
        audit_rule_free_data(rule);
    }
    if (rc < 0) {
        syslog(LOG_ERR, "audit_add_rule_data failed: %s", strerror(errno));
        return false;
    }
    return true;
}

void NetlinkReceiver::cleanupAuditRules() {
    struct audit_rule_data* rule = audit_rule_create_data();
    if (!rule) return;
    audit_rule_syscallbyname_data(rule, "execve");
    audit_rule_fieldpair_data(&rule, "arch=b64", AUDIT_FILTER_EXIT);
    rule->action = AUDIT_ALWAYS;
    rule->flags  = AUDIT_FILTER_EXIT;
    audit_delete_rule_data(m_auditFd, rule, AUDIT_FILTER_EXIT, AUDIT_ALWAYS);
    audit_rule_free_data(rule);
}
