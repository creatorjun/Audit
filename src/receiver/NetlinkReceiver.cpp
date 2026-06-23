// src/receiver/NetlinkReceiver.cpp
#include "NetlinkReceiver.hpp"
#include <libaudit.h>
#include <sys/epoll.h>
#include <auparse.h>
#include <unistd.h>
#include <cstring>
#include <stdexcept>
#include <syslog.h>

NetlinkReceiver::NetlinkReceiver(RawEventCallback cb)
    : m_callback(std::move(cb))
    , m_auditFd(-1)
    , m_epollFd(-1)
    , m_running(false)
{}

NetlinkReceiver::~NetlinkReceiver() {
    stop();
}

bool NetlinkReceiver::start() {
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

    m_running = true;
    run();
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

void NetlinkReceiver::run() {
    constexpr int MAX_EVENTS = 16;
    epoll_event events[MAX_EVENTS];
    char buf[8192];

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

            if (reply.type == AUDIT_EOE ||
                reply.type == AUDIT_SYSCALL ||
                reply.type == AUDIT_EXECVE ||
                reply.type == AUDIT_CWD ||
                reply.type == AUDIT_PATH) {

                AuditRawEvent ev;
                ev.type   = reply.type;
                ev.serial = reply.serial;
                if (reply.msg.data && reply.len > 0) {
                    ev.data.assign(reply.msg.data, reply.len);
                }
                m_callback(ev);
            }
        }
    }
}
