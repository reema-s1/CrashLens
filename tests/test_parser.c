#include <stdlib.h>
#include <string.h>

#include "crashlens/parser.h"
#include "parser_internal.h"
#include "test.h"

#define MAX_COLLECT 16

typedef struct {
    cl_crash_event_t events[MAX_COLLECT];
    size_t count;
    size_t stop_after; /* 0 = never stop */
} collector_t;

static int collect(cl_crash_event_t *ev, void *ctx)
{
    collector_t *c = ctx;

    if (c->count < MAX_COLLECT)
        c->events[c->count] = *ev;
    c->count++;
    return c->stop_after && c->count >= c->stop_after;
}

static collector_t *collector_new(void)
{
    return calloc(1, sizeof(collector_t));
}

static const char *read_fixture(const char *name, size_t *len)
{
    static char buf[16384];
    char path[512];
    FILE *fp;

    snprintf(path, sizeof(path), "%s/%s", TEST_DATA_DIR, name);
    fp = fopen(path, "rb");
    if (!fp)
        return NULL;
    *len = fread(buf, 1, sizeof(buf), fp);
    fclose(fp);
    return buf;
}

static void check_native_mixed(const collector_t *c, const cl_parse_stats_t *st)
{
    const cl_crash_event_t *ev;

    CHECK_INT(c->count, 3);
    CHECK_INT(st->events, 3);
    CHECK_INT(st->rejected, 1);
    CHECK_INT(st->truncated, 1);
    if (c->count < 3)
        return;

    ev = &c->events[0];
    CHECK_INT(ev->timestamp, 1790344991);
    CHECK_INT(ev->pid, 4121);
    CHECK_STR(ev->process, "indexer");
    CHECK_STR(ev->thread, "worker-3");
    CHECK_STR(ev->kind, "SIGSEGV");
    CHECK_INT(ev->signal, 11);
    CHECK_INT(ev->source_line, 3);
    CHECK_INT(ev->format, CL_FORMAT_NATIVE);
    CHECK_INT(ev->flags & CL_EVENT_TRUNCATED, 0);
    CHECK_INT(ev->frame_count, 5);
    CHECK_U64(ev->frames[0].address, 0x7f3a1c2b1c20);
    CHECK_STR(ev->frames[0].symbol, "parse_header");
    CHECK_U64(ev->frames[0].offset, 32);
    CHECK_STR(ev->frames[0].file, "codec.c");
    CHECK_INT(ev->frames[0].line, 118);
    CHECK_U64(ev->frames[1].offset, 0x90);
    CHECK_STR(ev->frames[2].symbol, "segment_load");
    CHECK_STR(ev->frames[2].file, "");
    CHECK_STR(ev->frames[3].symbol, "");
    CHECK(ev->frames[3].flags & CL_FRAME_HAS_ADDRESS);
    CHECK(!(ev->frames[3].flags & CL_FRAME_HAS_OFFSET));

    ev = &c->events[1];
    CHECK_INT(ev->timestamp, 1790341800);
    CHECK_STR(ev->kind, "std::out_of_range");
    CHECK_INT(ev->signal, 6);
    CHECK_INT(ev->frame_count, 2);
    CHECK_STR(ev->frames[0].symbol,
              "std::vector<int, std::allocator<int> >::at(unsigned long) const");
    CHECK_STR(ev->frames[1].symbol, "Index::lookup(Key const&)");
    CHECK_STR(ev->frames[1].file, "index.cc");
    CHECK_INT(ev->frames[1].line, 42);

    ev = &c->events[2];
    CHECK_INT(ev->pid, 99);
    CHECK_INT(ev->signal, 7);
    CHECK_STR(ev->kind, "SIGBUS");
    CHECK(ev->flags & CL_EVENT_TRUNCATED);
    CHECK_INT(ev->frame_count, 2);
    CHECK_STR(ev->frames[1].symbol, "main");
}

static void test_native_file(void)
{
    collector_t *c = collector_new();
    cl_parser_t *p = cl_parser_create(CL_FORMAT_AUTO, collect, c);
    char path[512];

    snprintf(path, sizeof(path), "%s/native_mixed.log", TEST_DATA_DIR);
    CHECK_INT(cl_parser_parse_file(p, path), CL_PARSE_OK);
    check_native_mixed(c, cl_parser_stats(p));
    if (c->count > 0)
        CHECK_STR(c->events[0].source, path);

    CHECK_INT(cl_parser_parse_file(p, "/nonexistent/crashlens.log"), CL_PARSE_IO);
    cl_parser_destroy(p);
    free(c);
}

static void test_byte_at_a_time(void)
{
    collector_t *c = collector_new();
    cl_parser_t *p = cl_parser_create(CL_FORMAT_NATIVE, collect, c);
    size_t len = 0, i;
    const char *data = read_fixture("native_mixed.log", &len);

    CHECK(data != NULL);
    if (data) {
        cl_parser_begin(p, "bytes");
        for (i = 0; i < len; i++)
            cl_parser_feed(p, data + i, 1);
        cl_parser_finish(p);
        check_native_mixed(c, cl_parser_stats(p));
    }
    cl_parser_destroy(p);
    free(c);
}

static void test_crlf_and_bom(void)
{
    static const char input[] =
        "\xEF\xBB\xBF=== CRASH ===\r\nSignal: SIGILL\r\nBacktrace:\r\n"
        "  #0 0x10 f + 1 (a.c:3)\r\n=== END ===\r\n";
    collector_t *c = collector_new();
    cl_parser_t *p = cl_parser_create(CL_FORMAT_AUTO, collect, c);

    cl_parser_parse_buffer(p, "crlf", input, sizeof(input) - 1);
    CHECK_INT(c->count, 1);
    CHECK_INT(c->events[0].signal, 4);
    CHECK_STR(c->events[0].frames[0].file, "a.c");
    CHECK_INT(c->events[0].frames[0].line, 3);
    CHECK_INT(c->events[0].flags & CL_EVENT_TRUNCATED, 0);
    cl_parser_destroy(p);
    free(c);
}

static void test_utf16(void)
{
    static const char ascii[] =
        "=== CRASH ===\r\nThread: T\xC3\xA9\r\nBacktrace:\r\n#0 0x1 g\r\n=== END ===\r\n";
    char wide[2 * sizeof(ascii) + 2];
    size_t i, n = 0;
    int be;

    for (be = 0; be <= 1; be++) {
        collector_t *c = collector_new();
        cl_parser_t *p = cl_parser_create(CL_FORMAT_AUTO, collect, c);

        n = 0;
        wide[n++] = be ? '\xFE' : '\xFF';
        wide[n++] = be ? '\xFF' : '\xFE';
        for (i = 0; i < sizeof(ascii) - 1; i++) {
            wide[n + (size_t)be] = ascii[i];
            wide[n + (size_t)!be] = '\0';
            n += 2;
        }
        cl_parser_parse_buffer(p, "utf16", wide, n);
        CHECK_INT(c->count, 1);
        CHECK_STR(c->events[0].frames[0].symbol, "g");
        /* Non-ASCII units are replaced, not dropped. */
        CHECK_STR(c->events[0].thread, "T??");
        cl_parser_destroy(p);
        free(c);
    }
}

static void test_overlong_line(void)
{
    collector_t *c = collector_new();
    cl_parser_t *p = cl_parser_create(CL_FORMAT_AUTO, collect, c);
    size_t n = CL_MAX_LINE * 3;
    char *big = malloc(n + 64);
    size_t len;

    memset(big, 'x', n);
    len = n;
    len += (size_t)sprintf(big + len, "\n=== CRASH ===\n#0 0x1 f\n");
    cl_parser_parse_buffer(p, "big", big, len);
    CHECK_INT(cl_parser_stats(p)->overlong_lines, 1);
    /* No "Backtrace:" line, so the frame is ignored and the report rejected. */
    CHECK_INT(c->count, 0);
    CHECK_INT(cl_parser_stats(p)->rejected, 1);
    cl_parser_destroy(p);
    free(big);
    free(c);
}

static void test_restart_marks_truncated(void)
{
    static const char input[] =
        "=== CRASH ===\nBacktrace:\n#0 0x1 a\n#1 0x2 b\n"
        "=== CRASH ===\nBacktrace:\n#0 0x1 c\n=== END ===\n";
    collector_t *c = collector_new();
    cl_parser_t *p = cl_parser_create(CL_FORMAT_AUTO, collect, c);

    cl_parser_parse_buffer(p, "restart", input, sizeof(input) - 1);
    CHECK_INT(c->count, 2);
    CHECK(c->events[0].flags & CL_EVENT_TRUNCATED);
    CHECK_INT(c->events[0].frame_count, 2);
    CHECK_INT(c->events[1].flags & CL_EVENT_TRUNCATED, 0);
    CHECK_STR(c->events[1].frames[0].symbol, "c");
    CHECK_INT(c->events[1].source_line, 5);
    cl_parser_destroy(p);
    free(c);
}

static void test_frame_ordering_and_garbage(void)
{
    static const char input[] =
        "=== CRASH ===\nBacktrace:\n"
        "#0 0x1 a\n"
        "#0 0x9 duplicate\n"       /* index went backwards: skipped */
        "#2 0x3 c\n"               /* gap is tolerated */
        "#3 notanaddress\n"
        "#4 0x99999999999999999 overflow\n"
        "#5 0x5\n"                 /* bare address, no symbol */
        "#6 0x6 d + (e.c:1)\n"     /* dangling '+' stays in the symbol */
        "trailing text ends the backtrace\n"
        "#7 0x7 ignored\n"
        "=== END ===\n";
    collector_t *c = collector_new();
    cl_parser_t *p = cl_parser_create(CL_FORMAT_AUTO, collect, c);
    const cl_crash_event_t *ev = &c->events[0];

    cl_parser_parse_buffer(p, "garbage", input, sizeof(input) - 1);
    CHECK_INT(c->count, 1);
    CHECK_INT(ev->frame_count, 4);
    CHECK_STR(ev->frames[0].symbol, "a");
    CHECK_STR(ev->frames[1].symbol, "c");
    CHECK_STR(ev->frames[2].symbol, "");
    CHECK_U64(ev->frames[2].address, 5);
    CHECK_STR(ev->frames[3].symbol, "d +");
    CHECK_STR(ev->frames[3].file, "e.c");
    cl_parser_destroy(p);
    free(c);
}

static void test_deep_stack(void)
{
    collector_t *c = collector_new();
    cl_parser_t *p = cl_parser_create(CL_FORMAT_AUTO, collect, c);
    char *buf = malloc(64 * 1024);
    size_t len = 0;
    int i;

    len += (size_t)sprintf(buf + len, "=== CRASH ===\nBacktrace:\n");
    for (i = 0; i < CL_MAX_STACK_DEPTH + 10; i++)
        len += (size_t)sprintf(buf + len, "#%d 0x%x recurse\n", i, i + 1);
    len += (size_t)sprintf(buf + len, "=== END ===\n");

    cl_parser_parse_buffer(p, "deep", buf, len);
    CHECK_INT(c->count, 1);
    CHECK_INT(c->events[0].frame_count, CL_MAX_STACK_DEPTH);
    CHECK(c->events[0].flags & CL_EVENT_STACK_TRUNCATED);
    cl_parser_destroy(p);
    free(buf);
    free(c);
}

static void test_callback_stop(void)
{
    static const char input[] =
        "=== CRASH ===\nBacktrace:\n#0 0x1 a\n=== END ===\n"
        "=== CRASH ===\nBacktrace:\n#0 0x1 b\n=== END ===\n";
    collector_t *c = collector_new();
    cl_parser_t *p = cl_parser_create(CL_FORMAT_AUTO, collect, c);

    c->stop_after = 1;
    CHECK_INT(cl_parser_parse_buffer(p, "stop", input, sizeof(input) - 1),
              CL_PARSE_STOPPED);
    CHECK_INT(c->count, 1);
    cl_parser_destroy(p);
    free(c);
}

static void test_split_file_line(void)
{
    cl_frame_t f;
    const char *s;

    memset(&f, 0, sizeof(f));
    s = "src/a.c:12:7";
    CHECK_INT(cl_split_file_line(s, s + strlen(s), &f), 0);
    CHECK_STR(f.file, "src/a.c");
    CHECK_INT(f.line, 12);

    s = "C:\\src\\b.c:9";
    CHECK_INT(cl_split_file_line(s, s + strlen(s), &f), 0);
    CHECK_STR(f.file, "C:\\src\\b.c");
    CHECK_INT(f.line, 9);

    /* The range end is honoured even when more digits follow it. */
    s = "c.c:345";
    CHECK_INT(cl_split_file_line(s, s + 6, &f), 0);
    CHECK_INT(f.line, 34);

    s = "nofile";
    CHECK_INT(cl_split_file_line(s, s + strlen(s), &f), -1);
    s = ":12";
    CHECK_INT(cl_split_file_line(s, s + strlen(s), &f), -1);
    s = "a.c:99999999999";
    CHECK_INT(cl_split_file_line(s, s + strlen(s), &f), -1);
}

const test_case_t parser_tests[] = {
    { "native_file", test_native_file },
    { "byte_at_a_time", test_byte_at_a_time },
    { "crlf_and_bom", test_crlf_and_bom },
    { "utf16", test_utf16 },
    { "overlong_line", test_overlong_line },
    { "restart_marks_truncated", test_restart_marks_truncated },
    { "frame_ordering_and_garbage", test_frame_ordering_and_garbage },
    { "deep_stack", test_deep_stack },
    { "callback_stop", test_callback_stop },
    { "split_file_line", test_split_file_line },
    { NULL, NULL },
};
