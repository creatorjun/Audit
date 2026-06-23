# CMakeLists.txt
cmake_minimum_required(VERSION 3.14)
project(audit-daemon VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ---------------------------------------------------------------------------
# libaudit 탐색: pkg-config 우선, 없으면 find_library / find_path 폴백
# ---------------------------------------------------------------------------
set(AUDIT_INCLUDE_DIRS "")
set(AUDIT_LIBRARIES    "")

find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(AUDIT QUIET audit)
endif()

if(AUDIT_FOUND)
    message(STATUS "libaudit: found via pkg-config (${AUDIT_VERSION})")
else()
    message(STATUS "libaudit: pkg-config unavailable or no .pc file, falling back to find_library")

    find_path(AUDIT_INCLUDE_DIR
        NAMES libaudit.h
        PATHS /usr/include /usr/local/include
    )
    find_library(AUDIT_LIBRARY
        NAMES audit
        PATHS /usr/lib64 /usr/lib /usr/local/lib64 /usr/local/lib
    )

    if(NOT AUDIT_INCLUDE_DIR)
        message(FATAL_ERROR
            "libaudit.h not found.\n"
            "  OL8:   sudo yum install audit-libs-devel\n"
            "  Ubuntu: sudo apt install libaudit-dev")
    endif()
    if(NOT AUDIT_LIBRARY)
        message(FATAL_ERROR
            "libaudit.so not found.\n"
            "  OL8:   sudo yum install audit-libs\n"
            "  Ubuntu: sudo apt install libaudit1")
    endif()

    set(AUDIT_INCLUDE_DIRS ${AUDIT_INCLUDE_DIR})
    set(AUDIT_LIBRARIES    ${AUDIT_LIBRARY})
    message(STATUS "  include: ${AUDIT_INCLUDE_DIR}")
    message(STATUS "  library: ${AUDIT_LIBRARY}")
endif()

# ---------------------------------------------------------------------------
# audisp 플러그인 디렉토리 자동 탐색
#   auditd 3.x+  → /etc/audit/plugins.d   (OL8 기본)
#   auditd 2.x   → /etc/audisp/plugins.d
# AUDISP_PLUGIN_DIR 캐시 변수로 수동 오버라이드 가능:
#   cmake .. -DAUDIOSP_PLUGIN_DIR=/etc/audisp/plugins.d
# ---------------------------------------------------------------------------
if(NOT DEFINED AUDISP_PLUGIN_DIR OR AUDISP_PLUGIN_DIR STREQUAL "")
    if(EXISTS "/etc/audit/plugins.d")
        set(AUDISP_PLUGIN_DIR "/etc/audit/plugins.d"
            CACHE PATH "audisp plugin directory" FORCE)
    elseif(EXISTS "/etc/audisp/plugins.d")
        set(AUDISP_PLUGIN_DIR "/etc/audisp/plugins.d"
            CACHE PATH "audisp plugin directory" FORCE)
    else()
        set(AUDISP_PLUGIN_DIR "/etc/audit/plugins.d"
            CACHE PATH "audisp plugin directory" FORCE)
        message(WARNING
            "audisp plugin directory not found. Defaulting to ${AUDISP_PLUGIN_DIR}.\n"
            "Override with: cmake .. -DAUDIOSP_PLUGIN_DIR=<path>")
    endif()
endif()
message(STATUS "audisp plugin dir: ${AUDISP_PLUGIN_DIR}")

# ---------------------------------------------------------------------------
# 빌드 타겟
# ---------------------------------------------------------------------------
set(SOURCES
    src/main.cpp
    src/daemon/AuditDaemon.cpp
    src/receiver/NetlinkReceiver.cpp
    src/parser/EventParser.cpp
    src/writer/LogWriter.cpp
)

add_executable(audit-daemon ${SOURCES})

target_include_directories(audit-daemon PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${AUDIT_INCLUDE_DIRS}
)
target_link_libraries(audit-daemon PRIVATE
    ${AUDIT_LIBRARIES}
    pthread
)
target_compile_options(audit-daemon PRIVATE -Wall -Wextra -O2)

# ---------------------------------------------------------------------------
# 설치
# ---------------------------------------------------------------------------
install(TARGETS audit-daemon
    DESTINATION /usr/local/sbin)
install(FILES config/audit-daemon.conf
    DESTINATION /etc/audit-daemon)
install(FILES systemd/audit-daemon.service
    DESTINATION /etc/systemd/system)
install(FILES config/audisp-plugin.conf
    DESTINATION ${AUDISP_PLUGIN_DIR}
    RENAME audit-daemon.conf)

# ---------------------------------------------------------------------------
# 테스트
# ---------------------------------------------------------------------------
enable_testing()
add_subdirectory(test)
