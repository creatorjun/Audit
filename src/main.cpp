// src/main.cpp
#include "daemon/AuditDaemon.hpp"
#include <syslog.h>
#include <cstdlib>

int main(int argc, char* argv[]) {
    openlog("audit-daemon", LOG_PID | LOG_CONS, LOG_DAEMON);

    std::string configPath = "/etc/audit-daemon/audit-daemon.conf";
    if (argc > 1) configPath = argv[1];

    DaemonConfig cfg;
    AuditDaemon::loadConfig(configPath, cfg);

    AuditDaemon daemon(cfg);
    daemon.run();

    closelog();
    return EXIT_SUCCESS;
}
