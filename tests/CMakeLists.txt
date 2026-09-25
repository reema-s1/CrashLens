add_executable(crashlens_tests
    test_fingerprint.c
    test_main.c
    test_parser.c
    test_util.c
)
target_link_libraries(crashlens_tests PRIVATE crashlens_core)
target_include_directories(crashlens_tests PRIVATE ${PROJECT_SOURCE_DIR}/src)
target_compile_definitions(crashlens_tests PRIVATE
    TEST_DATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}/data")

add_test(NAME unit COMMAND crashlens_tests)
