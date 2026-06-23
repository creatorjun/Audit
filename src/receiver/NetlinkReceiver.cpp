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

NetlinkReceiver::NetlinkReceiver(RawEventCallback cb, ReceiverMode mode, size_t maxQueue)
    : m_callback(std::move(cb))
    , m_mode(mode)
    , m_auditFd(-1)
    , m_epollFd(-1)
    , m_running(false)
    , m_maxQueue(maxQueue)
{}

NetlinkReceiver::~NetlinkReceiver() {
    stop();
}

bool NetlinkReceiver::start() {
    m_running = true;

    m_dispatchThread = std::thread(&NetlinkReceiver::dispatchLoop, this);

    if (m_mode == ReceiverMode::Dispatcher) {
        m_ioThread = std::thread(&NetlinkReceiver::runDispatcher, this);
    } else {
        m_auditFd = audit_open();
        if (m_auditFd < 0) {
            syslog(LOG_ERR, "audit_open failed: %s", strerror(errno));
            stop();
            return false;
        }
        if (audit_set_pid(m_auditFd, getpid(), WAIT_YES) < 0) {
            syslog(LOG_ERR, "audit_set_pid failed: %s", strerror(errno));
            stop();
            return false;
        }
        if (audit_set_enabled(m_auditFd, 1) < 0) {
            syslog(LOG_ERR, "audit_set_enabled failed");
            stop();
            return false;
        }
        if (!setupAuditRules()) {
            stop();
            return false;
        }
        m_epollFd = epoll_create1(EPOLL_CLOEXEC);
        if (m_epollFd < 0) {
            syslog(LOG_ERR, "epoll_create1 failed: %s", strerror(errno));
            stop();
            return false;
        }
        epoll_event ev{};
        ev.events  = EPOLLIN;
        ev.data.fd = m_auditFd;
        if (epoll_ctl(m_epollFd, EPOLL_CTL_ADD, m_auditFd, &ev) < 0) {
            syslog(LOG_ERR, "epoll_ctl failed: %s", strerror(errno));
            stop();
            return false;
        }
        m_ioThread = std::thread(&NetlinkReceiver::runStandalone, this);
    }
    return true;
}

void NetlinkReceiver::stop() {
    m_running = false;
    m_queueCv.notify_all();

    if (m_ioThread.joinable())       m_ioThread.join();
    if (m_dispatchThread.joinable()) m_dispatchThread.join();

    if (m_epollFd >= 0) { close(m_epollFd); m_epollFd = -1; }
    if (m_auditFd >= 0) {
        cleanupAuditRules();
        audit_set_pid(m_auditFd, 0, WAIT_NO);
        audit_close(m_auditFd);
        m_auditFd = -1;
    }
}

void NetlinkReceiver::dispatchLoop() {
    while (true) {
        std::unique_lock<std::mutex> lock(m_queueMutex);
        m_queueCv.wait(lock, [this] {
            return !m_rawQueue.empty() || !m_running;
        });

        while (!m_rawQueue.empty()) {
            AuditRawEvent ev = std::move(m_rawQueue.front());
            m_rawQueue.pop();
            lock.unlock();
            m_callback(ev);
            lock.lock();
        }

        if (!m_running && m_rawQueue.empty()) break;
    }
}

static void enqueueRaw(std::mutex& mtx, std::condition_variable& cv,
                       std::queue<AuditRawEvent>& q, size_t maxQ,
                       AuditRawEvent&& ev) {
    std::lock_guard<std::mutex> lock(mtx);
    if (q.size() >= maxQ) {
        syslog(LOG_WARNING, "NetlinkReceiver: raw queue full, dropping event serial=%lu",
               (unsigned long)ev.serial);
        return;
    }
    q.push(std::move(ev));
    cv.notify_one();
}

void NetlinkReceiver::runDispatcher() {
    syslog(LOG_INFO, "NetlinkReceiver: running in dispatcher mode (reading stdin)");

    int flags = fcntl(STDIN_FILENO, F_GETFL, 0);
    fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK);

    int epollFd = epoll_create1(EPOLL_CLOEXEC);
    if (epollFd < 0) {
        syslog(LOG_ERR, "epoll_create1 failed: %s", strerror(errno));
        m_running = false;
        m_queueCv.notify_all();
        return;
    }

    epoll_event ev{};
    ev.events  = EPOLLIN;
    ev.data.fd = STDIN_FILENO;
    epoll_ctl(epollFd, EPOLL_CTL_ADD, STDIN_FILENO, &ev);

    std::string lineBuf;
    lineBuf.reserve(4096);
    char buf[4096];

    while (m_running) {
        epoll_event events[8];
        int n = epoll_wait(epollFd, events, 8, 500);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        for (int i = 0; i < n; ++i) {
            if (!(events[i].events & EPOLLIN)) continue;
            ssize_t bytes;
            while ((bytes = read(STDIN_FILENO, buf, sizeof(buf))) > 0) {
                const char* p   = buf;
                const char* end = buf + bytes;
                while (p < end) {
                    const char* nl = static_cast<const char*>(memchr(p, '\n', end - p));
                    if (!nl) {
                        lineBuf.append(p, end - p);
                        p = end;
                    } else {
                        lineBuf.append(p, nl - p);
                        if (!lineBuf.empty()) {
                            AuditRawEvent rawEv;
                            if (parseLine(lineBuf, rawEv)) {
                                enqueueRaw(m_queueMutex, m_queueCv,
                                           m_rawQueue, m_maxQueue,
                                           std::move(rawEv));
                            }
                            lineBuf.clear();
                        }
                        p = nl + 1;
                    }
                }
            }
            if (bytes == 0) {
                syslog(LOG_INFO, "NetlinkReceiver: stdin EOF, auditd closed pipe");
                m_running = false;
                m_queueCv.notify_all();
                break;
            }
        }
    }
    close(epollFd);
}

bool NetlinkReceiver::parseLine(const std::string& line, AuditRawEvent& ev) {
    ev.timestamp = {};

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
    auto tsStart  = msgPos + 10;
    auto colonPos = line.find(':', tsStart);
    auto parenPos = line.find(')', colonPos != std::string::npos ? colonPos : tsStart);
    if (colonPos == std::string::npos || parenPos == std::string::npos) return false;

    try {
        double ts = std::stod(line.substr(tsStart, colonPos - tsStart));
        ev.timestamp.tv_sec  = static_cast<time_t>(ts);
        ev.timestamp.tv_nsec = static_cast<long>((ts - static_cast<double>(ev.timestamp.tv_sec)) * 1e9);
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
    struct audit_reply reply{};

    while (m_running) {
        int n = epoll_wait(m_epollFd, events, MAX_EVENTS, 500);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        for (int i = 0; i < n; ++i) {
            if (!(events[i].events & EPOLLIN)) continue;
            if (audit_get_reply(m_auditFd, &reply, GET_REPLY_NONBLOCKING, 0) <= 0) continue;

            AuditRawEvent rawEv;
            rawEv.type      = reply.type;
            rawEv.serial    = reply.nlh->nlmsg_seq;
            rawEv.timestamp = {};
            if (reply.message) rawEv.data = std::string(reply.message);

            enqueueRaw(m_queueMutex, m_queueCv,
                       m_rawQueue, m_maxQueue,
                       std::move(rawEv));
        }
    }

    m_queueCv.notify_all();
}

bool NetlinkReceiver::setupAuditRules() {
    audit_rule_data* rule = audit_rule_create_data();
    if (!rule) return false;

    audit_rule_syscallbyname_data(rule, "execve");
    audit_rule_syscallbyname_data(rule, "execveat");
    int rc = audit_add_rule_data(m_auditFd, rule, AUDIT_FILTER_EXIT, AUDIT_ALWAYS);
    free(rule);
    if (rc < 0) {
        syslog(LOG_ERR, "setupAuditRules: audit_add_rule_data failed: %s", strerror(errno));
        return false;
    }
    return true;
}

void NetlinkReceiver::cleanupAuditRules() {
    audit_rule_data* rule = audit_rule_create_data();
    if (!rule) return;
    audit_rule_syscallbyname_data(rule, "execve");
    audit_rule_syscallbyname_data(rule, "execveat");
    audit_delete_rule_data(m_auditFd, rule, AUDIT_FILTER_EXIT, AUDIT_ALWAYS);
    free(rule);
}
