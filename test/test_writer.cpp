// test/test_writer.cpp
#include "writer/LogWriter.hpp"
#include <cassert>
#include <iostream>
#include <fstream>
#include <thread>
#include <chrono>
#include <cstring>

int main() {
    const std::string testDir = "/tmp/audit-daemon-test";

    {
        LogWriter writer(testDir, 1, 1024);

        AuditRecord r{};
        r.serial        = 99999;
        r.timestamp     = {1719100800, 0};
        r.pid           = 1111;
        r.ppid          = 1000;
        r.uid           = 0;
        r.auid          = 1001;
        r.gid           = 0;
        r.comm          = "test";
        r.exe           = "/usr/bin/test";
        r.cmdline       = "test -f /tmp/hello";
        r.cwd           = "/tmp";
        r.tty           = "pts/0";
        r.hostname      = "192.168.1.1";
        r.success       = true;

        for (int i = 0; i < 10; ++i) {
            r.serial = 99999 + i;
            writer.enqueue(r);
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        writer.stop();
    }

    int lineCount = 0;
    bool found = false;
    for (auto& entry : {testDir}) {
        std::string pattern = testDir + "/";
        time_t now = time(nullptr);
        struct tm tm_info{};
        localtime_r(&now, &tm_info);
        char buf[16];
        strftime(buf, sizeof(buf), "%Y-%m-%d", &tm_info);
        std::string logPath = testDir + "/" + buf + ".log";
        std::ifstream f(logPath);
        std::string line;
        while (std::getline(f, line)) {
            ++lineCount;
            if (line.find("test -f /tmp/hello") != std::string::npos) found = true;
        }
    }

    assert(lineCount == 10);
    assert(found);

    std::cout << "test_writer: ALL PASSED (" << lineCount << " records written)" << std::endl;
    return 0;
}
