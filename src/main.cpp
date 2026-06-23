// src/main.cpp
#include "daemon/AuditDaemon.hpp"
#include <syslog.h>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <cstdlib>

static void signalHandler(int sig) {
    if (sig == SIGTERM || sig == SIGINT) {
        AuditDaemon::requestStop();
    }
}

static void daemonizeIfStandalone(ReceiverMode mode) {
    if (mode == ReceiverMode::Dispatcher) {
        // dispatcher 모드: auditd가 직접 fork하여 실행하므로 daemonize 불필요
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

    struct sigaction sa{};
    sa.sa_handler = signalHandler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGTERM, &sa, nullptr);
    sigaction(SIGINT,  &sa, nullptr);
    signal(SIGHUP, SIG_IGN);

    AuditDaemon daemon(cfg);
    daemon.run();

    closelog();
    return EXIT_SUCCESS;
}
