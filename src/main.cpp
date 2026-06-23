// src/main.cpp
#include "daemon/AuditDaemon.hpp"
#include <syslog.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <cstdlib>

static void daemonizeIfStandalone(ReceiverMode mode) {
    if (mode == ReceiverMode::Dispatcher) {
        return;
    }

    pid_t pid = fork();
    if (pid < 0) { exit(EXIT_FAILURE); }
    if (pid > 0) { exit(EXIT_SUCCESS); }
    if (setsid() < 0) { exit(EXIT_FAILURE); }

    pid = fork();
    if (pid < 0) { exit(EXIT_FAILURE); }
    if (pid > 0) { exit(EXIT_SUCCESS); }

    umask(0027);
    chdir("/");

    int devNull = open("/dev/null", O_RDWR);
    if (devNull >= 0) {
        dup2(devNull, STDIN_FILENO);
        dup2(devNull, STDOUT_FILENO);
        dup2(devNull, STDERR_FILENO);
        close(devNull);
    }
}

int main(int argc, char* argv[]) {
    openlog("audit-daemon", LOG_PID | LOG_CONS, LOG_DAEMON);

    std::string configPath = "/etc/audit-daemon/audit-daemon.conf";
    if (argc > 1) configPath = argv[1];

    DaemonConfig cfg;
    AuditDaemon::loadConfig(configPath, cfg);

    daemonizeIfStandalone(cfg.mode);

    AuditDaemon daemon(cfg);
    daemon.run();

    closelog();
    return EXIT_SUCCESS;
}
