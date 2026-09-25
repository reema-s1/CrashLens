#include <stdio.h>
#include <string.h>

#include "test.h"

int test_failures;

extern const test_case_t cluster_tests[];
extern const test_case_t fingerprint_tests[];
extern const test_case_t parser_tests[];
extern const test_case_t util_tests[];

static const struct {
    const char *name;
    const test_case_t *cases;
} suites[] = {
    { "util", util_tests },
    { "parser", parser_tests },
    { "fingerprint", fingerprint_tests },
    { "cluster", cluster_tests },
};

/* Usage: crashlens_tests [SUITE...]  -- runs every suite when none given. */
int main(int argc, char **argv)
{
    size_t s;
    int ran = 0;

    for (s = 0; s < sizeof(suites) / sizeof(suites[0]); s++) {
        const test_case_t *tc;
        int selected = argc < 2;
        int i;

        for (i = 1; i < argc; i++)
            if (strcmp(argv[i], suites[s].name) == 0)
                selected = 1;
        if (!selected)
            continue;

        for (tc = suites[s].cases; tc->name; tc++) {
            int before = test_failures;

            tc->fn();
            ran++;
            printf("%-4s %s.%s\n", test_failures == before ? "ok" : "FAIL",
                   suites[s].name, tc->name);
        }
    }

    printf("%d tests, %d failed checks\n", ran, test_failures);
    return test_failures == 0 && ran > 0 ? 0 : 1;
}
