// test/test_parser.cpp
#include "parser/EventParser.hpp"
#include <cassert>
#include <iostream>

int main() {
    std::vector<AuditRecord> results;

    EventParser parser([&](const AuditRecord& r) {
        results.push_back(r);
    });

    AuditRawEvent syscall;
    syscall.type   = AUDIT_SYSCALL;
    syscall.serial = 1000;
    syscall.data   = "arch=c000003e syscall=59 success=yes exit=0 "
                     "a0=55a1b2c3d4e5 a1=55a1b2c3d4f0 a2=55a1b2c3d500 a3=0 "
                     "items=2 ppid=1234 pid=5678 auid=1001 uid=0 gid=0 "
                     "euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 "
                     "tty=pts0 ses=5 comm=\"bash\" exe=\"/bin/bash\" "
                     "hostname=192.168.1.100 addr=192.168.1.100 "
                     "terminal=pts/0 res=success";

    AuditRawEvent execve;
    execve.type   = AUDIT_EXECVE;
    execve.serial = 1000;
    execve.data   = "argc=3 a0=\"cat\" a1=\"/etc\" a2=\"passwd\"";

    AuditRawEvent cwd;
    cwd.type   = AUDIT_CWD;
    cwd.serial = 1000;
    cwd.data   = "cwd=\"/home/testuser\"";

    AuditRawEvent eoe;
    eoe.type   = AUDIT_EOE;
    eoe.serial = 1000;
    eoe.data   = "";

    parser.onRawEvent(syscall);
    parser.onRawEvent(execve);
    parser.onRawEvent(cwd);
    parser.onRawEvent(eoe);

    assert(results.size() == 1);
    assert(results[0].pid  == 5678);
    assert(results[0].ppid == 1234);
    assert(results[0].auid == 1001);
    assert(results[0].cwd  == "/home/testuser");
    assert(results[0].cmdline == "cat /etc passwd");

    std::cout << "test_parser: ALL PASSED" << std::endl;
    return 0;
}
