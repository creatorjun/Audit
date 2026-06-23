# Audit Daemon

리눅스 서버에서 **누가 / 언제 / 어떤 명령어를 실행했는지** 추적하는 C++ 감사 데몬입니다.
TTY/PTY 레이어에 개입하지 않고 커널 `execve` syscall 이벤트만 수신하여
Hiware 등 접근제어 솔루션과의 충돌 없이 동작합니다.

---

## 목표

- 모든 사용자(SSH, Hiware, 터미널 직접 접속 포함)의 명령 실행을 빠짐없이 기록
- `su -` / `sudo` 전환 이후에도 원래 로그인 계정(`auid`) 역추적 유지
- 단일 C++ 데몬 프로세스로 상시 상주, 시스템 리소스 영향 최소화
- `systemd` unit으로 관리, 크래시 시 자동 재기동 보장

---

## 핵심 설계 원칙

### 왜 execve 후킹인가

```
[ 사용자 키입력 ]
       ↓
[ PTY/TTY 버퍼 ]   ← 키로깅 스크립트: 여기 개입 → Hiware와 TTY fd 경합 발생
       ↓
[ Shell (bash/sh) ]
       ↓
[ execve() syscall ]  ← 본 데몬: 여기서만 관찰 → 입력 스트림과 완전 분리
       ↓
[ 커널: 프로세스 생성 ]
```

- TTY 버퍼를 읽지 않으므로 Hiware 패스워드 자동 입력과 경합 없음
- `auid` (Audit User ID) 는 `su -` / `sudo` 전환 후에도 커널이 세션 전체에 보존
- 실제 책임 추적에 필요한 정보(누가/언제/무엇을)를 execve 이벤트 하나로 모두 수집 가능

---

## 시스템 구성

```
┌─────────────────────────────────────────────────────┐
│                    Linux Kernel                      │
│                                                      │
│  execve() ──► Audit Subsystem ──► Netlink Socket    │
└─────────────────────────────────┬───────────────────┘
                                  │ push (이벤트 드리븐)
┌─────────────────────────────────▼───────────────────┐
│                  audit-daemon (C++)                  │
│                                                      │
│  ┌──────────────────┐    ┌───────────────────────┐  │
│  │  NetlinkReceiver │───►│   EventParser          │  │
│  │  (epoll_wait)    │    │   (libaudit 구조체)    │  │
│  └──────────────────┘    └──────────┬────────────┘  │
│                                     │                │
│                          ┌──────────▼────────────┐  │
│                          │   LogWriter (thread)   │  │
│                          │   - 파일 rotate        │  │
│                          │   - syslog 선택 출력   │  │
│                          └───────────────────────┘  │
└─────────────────────────────────────────────────────┘
```

---

## 디렉토리 구조

```
Audit/
├── CMakeLists.txt
├── README.md
├── systemd/
│   └── audit-daemon.service
├── config/
│   └── audit-daemon.conf
├── src/
│   ├── main.cpp                  # 진입점, 시그널 핸들링, 데몬화
│   ├── daemon/
│   │   ├── AuditDaemon.hpp
│   │   └── AuditDaemon.cpp       # 메인 이벤트 루프
│   ├── receiver/
│   │   ├── NetlinkReceiver.hpp
│   │   └── NetlinkReceiver.cpp   # libaudit netlink 소켓, epoll
│   ├── parser/
│   │   ├── EventParser.hpp
│   │   └── EventParser.cpp       # audit 이벤트 → AuditRecord 변환
│   ├── writer/
│   │   ├── LogWriter.hpp
│   │   └── LogWriter.cpp         # 별도 스레드 비동기 로그 기록
│   └── model/
│       └── AuditRecord.hpp       # 이벤트 데이터 구조체
└── test/
    ├── test_parser.cpp
    └── test_writer.cpp
```

---

## 데이터 모델

```cpp
// src/model/AuditRecord.hpp
struct AuditRecord {
    uint64_t    serial;       // audit 이벤트 시리얼
    timespec    timestamp;    // 실행 시각 (nanosecond 정밀도)
    pid_t       pid;          // 실행 프로세스 PID
    pid_t       ppid;         // 부모 프로세스 PID
    uid_t       uid;          // 실제 UID (su 전환 후 변경됨)
    uid_t       auid;         // 원래 로그인 UID (세션 전체 보존)
    gid_t       gid;
    std::string comm;         // 프로세스 이름 (최대 15자)
    std::string exe;          // 실행 파일 전체 경로
    std::string cmdline;      // 전체 명령어 + 인자
    std::string cwd;          // 실행 시 작업 디렉토리
    std::string tty;          // TTY 장치명 (pts/0 등)
    std::string hostname;     // 접속 호스트명 (SSH/Hiware 원격 IP)
    int         exit_code;    // execve 반환값
};
```

---

## 구현 단계

### Phase 1: 기반 구조 (1주)

**목표:** 데몬 프로세스 뼈대 완성

- `main.cpp`: `fork()` + `setsid()` 데몬화, PID 파일 생성
- `AuditDaemon`: SIGTERM / SIGHUP 시그널 핸들링, graceful shutdown
- `CMakeLists.txt`: libaudit, pthread 링크 설정
- `systemd/audit-daemon.service`: `Restart=always`, `RestartSec=3`

```cmake
find_package(PkgConfig REQUIRED)
pkg_check_modules(AUDIT REQUIRED audit)
target_link_libraries(audit-daemon ${AUDIT_LIBRARIES} pthread)
```

### Phase 2: 이벤트 수신 (1주)

**목표:** 커널 execve 이벤트를 안정적으로 수신

- `NetlinkReceiver`: `audit_open()` → `audit_set_pid()` → `audit_set_enabled()`
- `epoll_wait()` 기반 블로킹 대기 (idle CPU 0%)
- `audit_add_rule_data()` 로 `AUDIT_EXECVE` + `AUDIT_SYSCALL` 규칙 등록
- 데몬 종료 시 `audit_delete_rule_data()` 로 규칙 정리

```
이벤트 수신 흐름:
AUDIT_SYSCALL  → pid, uid, auid, success, exe
AUDIT_EXECVE   → argc, argv (전체 명령어 인자)
AUDIT_CWD      → cwd
AUDIT_PATH     → 실행 파일 절대 경로
```

> **주의:** execve 1건은 위 4종류 레코드가 동일 serial로 묶여 도착함.
> serial 기준으로 레코드를 조립(assemble)한 뒤 완성된 AuditRecord를 생성해야 함.

### Phase 3: 파싱 및 조립 (1주)

**목표:** 멀티 레코드 → 단일 AuditRecord 조립

- `EventParser`: `serial → partial record map` 관리
- `AUDIT_EOE` (End of Event) 수신 시 조립 완료 처리
- 미완성 레코드 TTL 설정 (5초 초과 시 폐기, 메모리 누수 방지)
- `auid == 4294967295` (unset) 인 경우 시스템 데몬 판단 → 필터링 옵션

### Phase 4: 로그 기록 (1주)

**목표:** 비동기 로그 기록, 유실 없음 보장

- `LogWriter`: 별도 스레드 + `std::queue<AuditRecord>` + `std::mutex`
- 메인 이벤트 루프 블로킹 방지 (I/O 지연이 수신에 영향 없음)
- 로그 포맷 (JSON Lines):

```json
{
  "ts": "2026-06-23T09:15:00.123456789+09:00",
  "serial": 12345678,
  "pid": 4521,
  "ppid": 4520,
  "uid": 0,
  "auid": 1001,
  "auid_name": "junhee",
  "exe": "/usr/bin/cat",
  "cmdline": "cat /etc/passwd",
  "cwd": "/home/junhee",
  "tty": "pts/1",
  "hostname": "192.168.1.100"
}
```

- 일별 로그 로테이션: `/var/log/audit-daemon/YYYY-MM-DD.log`
- `config/audit-daemon.conf` 로 로그 경로, 보존 기간, 필터 UID 설정

### Phase 5: 검증 및 배포 (1주)

- `test/test_parser.cpp`: 멀티 레코드 조립 유닛 테스트
- `test/test_writer.cpp`: 큐 동시성 테스트
- Hiware 환경에서 `su -` 패스워드 자동 입력 충돌 없음 확인
- `/var/log/audit-daemon/` 파일 권한 `640`, 소유자 `root:adm`
- `auditd` 와 동시 실행 충돌 여부 확인 (netlink PID 중복 주의)

---

## 빌드 방법

```bash
git clone https://github.com/creatorjun/Audit.git
cd Audit
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
sudo make install
```

**의존성:**

```bash
# Ubuntu/Debian
sudo apt install libaudit-dev cmake g++

# RHEL/CentOS
sudo yum install audit-libs-devel cmake gcc-c++
```

---

## 설치 및 실행

```bash
# systemd 등록
sudo cp systemd/audit-daemon.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now audit-daemon

# 상태 확인
sudo systemctl status audit-daemon

# 로그 실시간 확인
sudo tail -f /var/log/audit-daemon/$(date +%Y-%m-%d).log | jq .
```

---

## auditd 와의 관계

| 항목 | auditd | 본 데몬 |
|---|---|---|
| 목적 | 범용 커널 감사 | execve 특화 명령 추적 |
| 로그 형식 | auditd 전용 포맷 | JSON Lines (파싱 용이) |
| Hiware 호환 | 호환 | 호환 |
| 동시 실행 | - | netlink PID 충돌 주의, 규칙만 분리하면 공존 가능 |

auditd 가 이미 설치된 환경에서는 `audit_set_pid()` 경합을 피하기 위해
auditd 규칙에 execve를 추가하고 본 데몬은 dispatcher 모드로 운용하는 것을 권장합니다.

---

## 라이선스

MIT
