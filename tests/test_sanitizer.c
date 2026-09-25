#include <stdlib.h>
#include <string.h>

#include "crashlens/fingerprint.h"
#include "crashlens/parser.h"
#include "test.h"

#define MAX_EVENTS 8

typedef struct {
    cl_crash_event_t events[MAX_EVENTS];
    size_t count;
} events_t;

static int keep(cl_crash_event_t *ev, void *ctx)
{
    events_t *e = ctx;

    if (e->count < MAX_EVENTS)
        e->events[e->count] = *ev;
    e->count++;
    return 0;
}

static events_t *parse_fixture(cl_log_format_t fmt, cl_parse_stats_t *stats)
{
    events_t *e = calloc(1, sizeof(*e));
    cl_parser_t *p = cl_parser_create(fmt, keep, e);
    char path[512];

    snprintf(path, sizeof(path), "%s/sanitizer.log", TEST_DATA_DIR);
    CHECK_INT(cl_parser_parse_file(p, path), CL_PARSE_OK);
    *stats = *cl_parser_stats(p);
    cl_parser_destroy(p);
    return e;
}

static void test_reports(void)
{
    cl_parse_stats_t st;
    events_t *e = parse_fixture(CL_FORMAT_AUTO, &st);
    const cl_crash_event_t *ev;
    const cl_frame_t *f;

    CHECK_INT(e->count, 6);
    CHECK_INT(st.rejected, 0);
    CHECK_INT(st.truncated, 0);
    if (e->count != 6)
        goto out;

    /* Only the faulting stack is kept, not the free/alloc stacks. */
    ev = &e->events[0];
    CHECK_INT(ev->format, CL_FORMAT_SANITIZER);
    CHECK_STR(ev->kind, "heap-use-after-free");
    CHECK_INT(ev->pid, 4121);
    CHECK_STR(ev->thread, "T3");
    CHECK_INT(ev->source_line, 3);
    CHECK_INT(ev->frame_count, 4);
    f = &ev->frames[0];
    CHECK_U64(f->address, 0x55555555d0c4);
    CHECK_STR(f->symbol, "parse_header");
    CHECK_STR(f->file, "/src/indexer/codec.c");
    CHECK_INT(f->line, 118);
    CHECK_STR(ev->frames[2].symbol, "Segment::load(std::string const&)");
    CHECK_INT(ev->frames[2].line, 40);
    f = &ev->frames[3];
    CHECK_STR(f->symbol, "start_thread");
    CHECK_STR(f->file, "/lib/x86_64-linux-gnu/libc.so.6");
    CHECK_U64(f->offset, 0x94ac3);
    CHECK(f->flags & CL_FRAME_MODULE_RELATIVE);

    ev = &e->events[2];
    CHECK_STR(ev->kind, "SIGSEGV");
    CHECK_INT(ev->signal, 11);
    CHECK_INT(ev->frame_count, 3);
    CHECK_STR(ev->frames[0].symbol, "(anonymous namespace)::lookup(Index const&, int)");
    CHECK_STR(ev->frames[0].file, "/src/indexer/index.cc");
    CHECK_STR(ev->frames[2].symbol, "");
    CHECK_STR(ev->frames[2].file, "");

    ev = &e->events[3];
    CHECK_STR(ev->kind, "memory-leak");
    CHECK_INT(ev->frame_count, 2);
    CHECK_STR(ev->frames[1].symbol, "make_buffer");

    /* A native report straight after a sanitizer stack is still found. */
    ev = &e->events[4];
    CHECK_INT(ev->format, CL_FORMAT_NATIVE);
    CHECK_STR(ev->frames[2].symbol, "check_invariants");

    /* A stack that runs to the end of the input is complete. */
    ev = &e->events[5];
    CHECK_STR(ev->kind, "stack-overflow");
    CHECK_INT(ev->frame_count, 1);
    CHECK_INT(ev->flags & CL_EVENT_TRUNCATED, 0);

out:
    free(e);
}

static void test_same_bug_same_fingerprint(void)
{
    cl_parse_stats_t st;
    events_t *e = parse_fixture(CL_FORMAT_AUTO, &st);
    cl_fp_options_t o;

    cl_fp_options_default(&o);
    if (e->count >= 3) {
        /* Different PIDs, threads and ASLR bases; one symbol is a clone. */
        CHECK_U64(cl_fingerprint(&e->events[0], &o), cl_fingerprint(&e->events[1], &o));
        CHECK(cl_fingerprint(&e->events[0], &o) != cl_fingerprint(&e->events[2], &o));
    }
    free(e);
}

static void test_format_filter(void)
{
    cl_parse_stats_t st;
    events_t *e = parse_fixture(CL_FORMAT_SANITIZER, &st);

    CHECK_INT(e->count, 5);
    free(e);
    e = parse_fixture(CL_FORMAT_NATIVE, &st);
    CHECK_INT(e->count, 1);
    free(e);
}

static void test_malformed(void)
{
    static const char input[] =
        "==1==ERROR: AddressSanitizer: SEGV on unknown address\n"
        "SUMMARY: AddressSanitizer: SEGV\n"                   /* no stack */
        "==2==ERROR: AddressSanitizer: attempting double-free on 0x1\n"
        "    #1 0x10 in not_first\n"                          /* must start at #0 */
        "    #0 0x11 in first\n"
        "    #1 0x12\n"                                        /* bare address */
        "    #2 0x13 in ?? (lib.so+0x40)\n"
        "    #3 0x14 in f (lib.so+zz)\n"
        "    #4 0x15 in g (+0x10)\n"
        "    #5 bogus\n"                                       /* skipped */
        "    #6 0x16 in h /a b/c.c:3\n"
        "    #0 0x17 in second_stack\n"
        "==x==ERROR: AddressSanitizer: nope\n"
        "==3==ERROR: something else\n";
    events_t *e = calloc(1, sizeof(*e));
    cl_parser_t *p = cl_parser_create(CL_FORMAT_AUTO, keep, e);
    const cl_crash_event_t *ev = &e->events[0];

    cl_parser_parse_buffer(p, "malformed", input, sizeof(input) - 1);
    CHECK_INT(e->count, 1);
    CHECK_INT(cl_parser_stats(p)->rejected, 1);
    CHECK_STR(ev->kind, "double-free");
    CHECK_INT(ev->frame_count, 6);
    if (ev->frame_count == 6) {
        CHECK_STR(ev->frames[0].symbol, "first");
        CHECK_STR(ev->frames[1].symbol, "");
        CHECK_STR(ev->frames[2].symbol, "");
        CHECK_STR(ev->frames[2].file, "lib.so");
        CHECK_STR(ev->frames[3].symbol, "f (lib.so+zz)");
        CHECK_STR(ev->frames[4].symbol, "g (+0x10)");
        CHECK_STR(ev->frames[5].symbol, "h /a");
        CHECK_STR(ev->frames[5].file, "b/c.c");
    }
    cl_parser_destroy(p);
    free(e);
}

static void test_preamble_limit(void)
{
    events_t *e = calloc(1, sizeof(*e));
    cl_parser_t *p = cl_parser_create(CL_FORMAT_AUTO, keep, e);
    char *buf = malloc(8192);
    size_t len = 0;
    int i;

    len += (size_t)sprintf(buf, "==1==ERROR: AddressSanitizer: SEGV\n");
    for (i = 0; i < 100; i++)
        len += (size_t)sprintf(buf + len, "noise %d\n", i);
    len += (size_t)sprintf(buf + len, "    #0 0x1 in too_late\n");
    cl_parser_parse_buffer(p, "preamble", buf, len);
    CHECK_INT(e->count, 0);
    CHECK_INT(cl_parser_stats(p)->rejected, 1);
    cl_parser_destroy(p);
    free(buf);
    free(e);
}

const test_case_t sanitizer_tests[] = {
    { "reports", test_reports },
    { "same_bug_same_fingerprint", test_same_bug_same_fingerprint },
    { "format_filter", test_format_filter },
    { "malformed", test_malformed },
    { "preamble_limit", test_preamble_limit },
    { NULL, NULL },
};
