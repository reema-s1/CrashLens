#include <stdint.h>

#include "crashlens/crash_event.h"
#include "test.h"
#include "util.h"

static void test_strlcpy_truncates(void)
{
    char buf[4];

    CHECK_INT(cl_strlcpy(buf, "abcdef", sizeof(buf)), 6);
    CHECK_STR(buf, "abc");
    cl_strlcpyn(buf, "xyz", 2, sizeof(buf));
    CHECK_STR(buf, "xy");
}

static void test_parse_u64(void)
{
    const char *s = "0x1F rest";
    uint64_t v = 0;

    CHECK_INT(cl_parse_u64(&s, 16, &v), 0);
    CHECK_U64(v, 0x1f);
    CHECK_STR(s, " rest");

    s = "18446744073709551615";
    CHECK_INT(cl_parse_u64(&s, 10, &v), 0);
    CHECK_U64(v, UINT64_MAX);

    s = "18446744073709551616";
    CHECK_INT(cl_parse_u64(&s, 10, &v), -1);

    s = "0x10000000000000000";
    CHECK_INT(cl_parse_u64(&s, 16, &v), -1);

    s = "zz";
    CHECK_INT(cl_parse_u64(&s, 10, &v), -1);

    /* A bare "0x" is a zero followed by garbage, not a hex prefix. */
    s = "0x";
    CHECK_INT(cl_parse_u64(&s, 16, &v), 0);
    CHECK_U64(v, 0);
    CHECK_STR(s, "x");

    s = "1234";
    CHECK_INT(cl_parse_hex_addr(&s, &v), -1);
}

static void test_iso8601(void)
{
    int64_t t = 0;
    char buf[32];

    CHECK_INT(cl_parse_iso8601("1970-01-01T00:00:00Z", &t), 0);
    CHECK_INT(t, 0);

    CHECK_INT(cl_parse_iso8601("2026-09-25T14:03:11Z", &t), 0);
    CHECK_INT(t, 1790344991);
    cl_format_iso8601(t, buf, sizeof(buf));
    CHECK_STR(buf, "2026-09-25T14:03:11Z");

    CHECK_INT(cl_parse_iso8601("2026-09-25 16:03:11.250+02:00", &t), 0);
    CHECK_INT(t, 1790344991);

    CHECK_INT(cl_parse_iso8601("2024-02-29T00:00:00", &t), 0);
    CHECK_INT(cl_parse_iso8601("2023-02-29T00:00:00", &t), -1);
    CHECK_INT(cl_parse_iso8601("2026-13-01T00:00:00", &t), -1);
    CHECK_INT(cl_parse_iso8601("2026-09-25T24:00:00", &t), -1);
    CHECK_INT(cl_parse_iso8601("2026-09-25", &t), -1);
    CHECK_INT(cl_parse_iso8601("2026-09-25T14:03:11Zjunk", &t), -1);
    CHECK_INT(cl_parse_iso8601("", &t), -1);

    cl_format_iso8601(-1, buf, sizeof(buf));
    CHECK_STR(buf, "1969-12-31T23:59:59Z");
}

static void test_basename(void)
{
    CHECK_STR(cl_basename("/usr/lib/libc.so.6"), "libc.so.6");
    CHECK_STR(cl_basename("C:\\build\\app.exe"), "app.exe");
    CHECK_STR(cl_basename("plain"), "plain");
}

static void test_signals_and_formats(void)
{
    cl_log_format_t fmt;

    CHECK_INT(cl_signal_from_name("SIGSEGV"), 11);
    CHECK_INT(cl_signal_from_name("SEGV"), 11);
    CHECK_INT(cl_signal_from_name("SIGNOPE"), 0);
    CHECK_STR(cl_signal_name(6), "SIGABRT");
    CHECK(cl_signal_name(999) == NULL);

    CHECK_INT(cl_format_from_name("sanitizer", &fmt), 0);
    CHECK_INT(fmt, CL_FORMAT_SANITIZER);
    CHECK_INT(cl_format_from_name("xml", &fmt), -1);
    CHECK_STR(cl_format_name(CL_FORMAT_NATIVE), "native");
}

static void test_push_frame_limit(void)
{
    static cl_crash_event_t ev;
    int i;

    cl_event_reset(&ev);
    for (i = 0; i < CL_MAX_STACK_DEPTH; i++)
        CHECK(cl_event_push_frame(&ev) != NULL);
    CHECK(cl_event_push_frame(&ev) == NULL);
    CHECK_INT(ev.frame_count, CL_MAX_STACK_DEPTH);
    CHECK(ev.flags & CL_EVENT_STACK_TRUNCATED);
}

const test_case_t util_tests[] = {
    { "strlcpy_truncates", test_strlcpy_truncates },
    { "parse_u64", test_parse_u64 },
    { "iso8601", test_iso8601 },
    { "basename", test_basename },
    { "signals_and_formats", test_signals_and_formats },
    { "push_frame_limit", test_push_frame_limit },
    { NULL, NULL },
};
