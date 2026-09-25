#ifndef CRASHLENS_TEST_H
#define CRASHLENS_TEST_H

/* A deliberately small test harness: each test is a void function, checks
 * record failures and keep going so one run reports every broken check. */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    const char *name;
    void (*fn)(void);
} test_case_t;

extern int test_failures;

#define CHECK(cond)                                                          \
    do {                                                                     \
        if (!(cond)) {                                                       \
            fprintf(stderr, "  %s:%d: CHECK(%s) failed\n", __FILE__,         \
                    __LINE__, #cond);                                        \
            test_failures++;                                                 \
        }                                                                    \
    } while (0)

#define CHECK_INT(actual, expected)                                          \
    do {                                                                     \
        long long a_ = (long long)(actual), e_ = (long long)(expected);      \
        if (a_ != e_) {                                                      \
            fprintf(stderr, "  %s:%d: %s == %lld, expected %lld\n",          \
                    __FILE__, __LINE__, #actual, a_, e_);                    \
            test_failures++;                                                 \
        }                                                                    \
    } while (0)

#define CHECK_U64(actual, expected)                                          \
    do {                                                                     \
        uint64_t a_ = (uint64_t)(actual), e_ = (uint64_t)(expected);         \
        if (a_ != e_) {                                                      \
            fprintf(stderr, "  %s:%d: %s == 0x%llx, expected 0x%llx\n",      \
                    __FILE__, __LINE__, #actual, (unsigned long long)a_,     \
                    (unsigned long long)e_);                                 \
            test_failures++;                                                 \
        }                                                                    \
    } while (0)

#define CHECK_STR(actual, expected)                                          \
    do {                                                                     \
        const char *a_ = (actual), *e_ = (expected);                         \
        if (strcmp(a_, e_) != 0) {                                           \
            fprintf(stderr, "  %s:%d: %s == \"%s\", expected \"%s\"\n",      \
                    __FILE__, __LINE__, #actual, a_, e_);                    \
            test_failures++;                                                 \
        }                                                                    \
    } while (0)

/* Absolute path of tests/data, supplied by the build. */
#ifndef TEST_DATA_DIR
#define TEST_DATA_DIR "tests/data"
#endif

#endif
