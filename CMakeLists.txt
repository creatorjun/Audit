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
        PATHS
            /usr/include
            /usr/local/include
    )

    find_library(AUDIT_LIBRARY
        NAMES audit
        PATHS
            /usr/lib64
            /usr/lib
            /usr/local/lib64
            /usr/local/lib
    )

    if(NOT AUDIT_INCLUDE_DIR)
        message(FATAL_ERROR
            "libaudit.h not found.\n"
            "  OL8: sudo yum install audit-libs-devel\n"
            "  Ubuntu: sudo apt install libaudit-dev")
    endif()

    if(NOT AUDIT_LIBRARY)
        message(FATAL_ERROR
            "libaudit.so not found.\n"
            "  OL8: sudo yum install audit-libs\n"
            "  Ubuntu: sudo apt install libaudit1")
    endif()

    set(AUDIT_INCLUDE_DIRS ${AUDIT_INCLUDE_DIR})
    set(AUDIT_LIBRARIES    ${AUDIT_LIBRARY})
    message(STATUS "  include: ${AUDIT_INCLUDE_DIR}")
    message(STATUS "  library: ${AUDIT_LIBRARY}")
endif()

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
install(TARGETS audit-daemon DESTINATION /usr/local/sbin)
install(FILES config/audit-daemon.conf DESTINATION /etc/audit-daemon)
install(FILES systemd/audit-daemon.service DESTINATION /etc/systemd/system)

# ---------------------------------------------------------------------------
# 테스트
# ---------------------------------------------------------------------------
enable_testing()
add_subdirectory(test)
