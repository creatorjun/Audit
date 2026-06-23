// src/receiver/NetlinkReceiver.cpp
#include "NetlinkReceiver.hpp"
#include <syslog.h>
#include <unistd.h>
#include <poll.h>
#include <sstream>
#include <cstring>
#include <cstdio>

NetlinkReceiver::NetlinkReceiver(RawEventCb cb)
    : m_cb(std::move(cb))
{}

bool NetlinkReceiver::start() {
    m_running = true;
    syslog(LOG_INFO, "NetlinkReceiver: running in dispatcher mode (reading stdin)");
    runDispatcher();
    return true;
}

void NetlinkReceiver::stop() {
    m_running = false;
}

void NetlinkReceiver::runDispatcher() {
    std::string lineBuf;
    lineBuf.reserve(4096);

    struct pollfd pfd{};
    pfd.fd     = STDIN_FILENO;
    pfd.events = POLLIN;

    char buf[4096];

    while (m_running) {
        int ret = poll(&pfd, 1, 500);
        if (ret < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (ret == 0) continue;
        if (!(pfd.revents & POLLIN)) break;

        ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));
        if (n <= 0) break;

        for (ssize_t j = 0; j < n; ++j) {
            if (buf[j] == '\n') {
                if (!lineBuf.empty()) {
                    AuditRawEvent ev{};
                    if (parseLine(lineBuf, ev)) m_cb(ev);
                    lineBuf.clear();
                    lineBuf.reserve(4096);
                }
            } else {
                lineBuf += buf[j];
            }
        }
    }
}

bool NetlinkReceiver::parseLine(const std::string& line, AuditRawEvent& ev) {
    auto typePos = line.find("type=");
    if (typePos == std::string::npos) return false;

    auto typeEnd = line.find(' ', typePos);
    std::string typeStr = line.substr(typePos + 5,
        typeEnd == std::string::npos ? std::string::npos : typeEnd - typePos - 5);

    auto msgPos = line.find("msg=audit(");
    if (msgPos == std::string::npos) return false;

    auto tsStart  = msgPos + 10;
    auto colonPos = line.find(':', tsStart);
    auto parenPos = line.find(')', tsStart);
    if (colonPos == std::string::npos || parenPos == std::string::npos) return false;

    try {
        ev.timestamp = std::stod(line.substr(tsStart, colonPos - tsStart));
        ev.serial    = std::stoull(line.substr(colonPos + 1, parenPos - colonPos - 1));
    } catch (...) { return false; }

    auto dataStart = line.find(')', parenPos);
    if (dataStart == std::string::npos) return false;
    dataStart += 2;

    ev.data = (dataStart < line.size()) ? line.substr(dataStart) : "";

    if      (typeStr == "SYSCALL") ev.type = 1309;
    else if (typeStr == "EXECVE")  ev.type = 1311;
    else if (typeStr == "CWD")     ev.type = 1307;
    else if (typeStr == "PATH")    ev.type = 1302;
    else if (typeStr == "EOE")     ev.type = 1320;
    else {
        try { ev.type = std::stoi(typeStr); }
        catch (...) { ev.type = 0; }
    }

    return true;
}
