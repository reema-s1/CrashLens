# Fuzz targets. Each target is a plain LLVMFuzzerTestOneInput and is built
# twice when possible:
#   fuzz_<name>            with the bundled mutation driver (any compiler)
#   fuzz_<name>_libfuzzer  with libFuzzer (Clang, CRASHLENS_LIBFUZZER=ON)

set(FUZZ_SEEDS_parser
    ${PROJECT_SOURCE_DIR}/tests/data/native_mixed.log
    ${PROJECT_SOURCE_DIR}/tests/data/sanitizer.log
    ${PROJECT_SOURCE_DIR}/tests/data/unsymbolicated.log)
set(FUZZ_SEEDS_symbols
    ${PROJECT_SOURCE_DIR}/tests/data/indexer.sym)

set(CRASHLENS_FUZZ_ITERATIONS 5000 CACHE STRING
    "Mutations per fuzz target when run from CTest")

foreach(target parser symbols)
    add_executable(fuzz_${target} fuzz_${target}.c standalone.c)
    target_link_libraries(fuzz_${target} PRIVATE crashlens_core)

    if(CRASHLENS_BUILD_TESTS)
        add_test(NAME fuzz_${target}
                 COMMAND fuzz_${target} -n ${CRASHLENS_FUZZ_ITERATIONS} -s 1
                         ${FUZZ_SEEDS_${target}})
    endif()

    if(CRASHLENS_LIBFUZZER)
        add_executable(fuzz_${target}_libfuzzer fuzz_${target}.c)
        target_link_libraries(fuzz_${target}_libfuzzer PRIVATE crashlens_core)
        target_compile_options(fuzz_${target}_libfuzzer PRIVATE -fsanitize=fuzzer)
        target_link_options(fuzz_${target}_libfuzzer PRIVATE -fsanitize=fuzzer)
    endif()
endforeach()
