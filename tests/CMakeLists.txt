add_executable(crashlens_tests
    test_cluster.c
    test_fingerprint.c
    test_main.c
    test_parser.c
    test_report.c
    test_symbols.c
    test_util.c
)
target_link_libraries(crashlens_tests PRIVATE crashlens_core)
target_include_directories(crashlens_tests PRIVATE ${PROJECT_SOURCE_DIR}/src)
target_compile_definitions(crashlens_tests PRIVATE
    TEST_DATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}/data")

add_test(NAME unit COMMAND crashlens_tests)

# End-to-end checks of the command-line tool.
add_test(NAME cli_report COMMAND crashlens ${CMAKE_CURRENT_SOURCE_DIR}/data/native_mixed.log)
set_tests_properties(cli_report PROPERTIES
    PASS_REGULAR_EXPRESSION "3 parsed [(]1 truncated[)], 1 rejected")

add_test(NAME cli_json COMMAND crashlens --json --top 1 ${CMAKE_CURRENT_SOURCE_DIR}/data)
set_tests_properties(cli_json PROPERTIES PASS_REGULAR_EXPRESSION "\"rank\": 1,")

add_test(NAME cli_unknown_option COMMAND crashlens --no-such-option x)
set_tests_properties(cli_unknown_option PROPERTIES WILL_FAIL TRUE)

add_test(NAME cli_missing_input COMMAND crashlens ${CMAKE_CURRENT_SOURCE_DIR}/data/does-not-exist.log)
set_tests_properties(cli_missing_input PROPERTIES WILL_FAIL TRUE)

add_test(NAME cli_symbols COMMAND crashlens
    --symbols ${CMAKE_CURRENT_SOURCE_DIR}/data/indexer.sym --load-bias 0x555555400000
    ${CMAKE_CURRENT_SOURCE_DIR}/data/unsymbolicated.log)
set_tests_properties(cli_symbols PROPERTIES
    PASS_REGULAR_EXPRESSION "1 distinct from 2 crashes.*parse_header [+] 0x20")

add_test(NAME cli_missing_symbols COMMAND crashlens
    --symbols ${CMAKE_CURRENT_SOURCE_DIR}/data/does-not-exist.sym
    ${CMAKE_CURRENT_SOURCE_DIR}/data/unsymbolicated.log)
set_tests_properties(cli_missing_symbols PROPERTIES WILL_FAIL TRUE)
