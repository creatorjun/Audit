# test/CMakeLists.txt
find_package(PkgConfig REQUIRED)
pkg_check_modules(AUDIT REQUIRED audit)

add_executable(test_parser
    test_parser.cpp
    ../src/parser/EventParser.cpp
)
target_include_directories(test_parser PRIVATE ../src ${AUDIT_INCLUDE_DIRS})
target_link_libraries(test_parser PRIVATE ${AUDIT_LIBRARIES} pthread)

add_executable(test_writer
    test_writer.cpp
    ../src/writer/LogWriter.cpp
)
target_include_directories(test_writer PRIVATE ../src)
target_link_libraries(test_writer PRIVATE pthread)

add_test(NAME test_parser COMMAND test_parser)
add_test(NAME test_writer COMMAND test_writer)
