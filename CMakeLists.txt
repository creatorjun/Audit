# CMakeLists.txt
cmake_minimum_required(VERSION 3.16)
project(audit-daemon VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(PkgConfig REQUIRED)
pkg_check_modules(AUDIT REQUIRED audit)

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

install(TARGETS audit-daemon DESTINATION /usr/local/sbin)
install(FILES config/audit-daemon.conf DESTINATION /etc/audit-daemon)
install(FILES systemd/audit-daemon.service DESTINATION /etc/systemd/system)

enable_testing()
add_subdirectory(test)
