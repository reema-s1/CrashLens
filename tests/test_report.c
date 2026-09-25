#include <stdlib.h>
#include <string.h>

#include "crashlens/report.h"
#include "test.h"

static cl_crash_event_t *event(const char *source, int64_t ts, const char *top,
                               int with_lines)
{
    static cl_crash_event_t ev;
    cl_frame_t *f;

    cl_event_reset(&ev);
    strcpy(ev.source, source);
    strcpy(ev.kind, "SIGSEGV");
    ev.signal = 11;
    ev.timestamp = ts;
    ev.pid = 42;
    f = cl_event_push_frame(&ev);
    strcpy(f->symbol, top);
    f->address = 0x401000;
    f->flags = CL_FRAME_HAS_ADDRESS;
    if (with_lines) {
        strcpy(f->file, "a.c");
        f->line = 10;
    }
    f = cl_event_push_frame(&ev);
    strcpy(f->symbol, "main");
    return &ev;
}

static char *render(int json, const cl_cluster_table_t *t,
                    const cl_report_options_t *opts)
{
    static char buf[32768];
    const char *path = "crashlens_report_test.out";
    FILE *fp = fopen(path, "w+b");
    size_t n;

    if (!fp)
        return NULL;
    CHECK_INT(json ? cl_report_json(fp, t, opts) : cl_report_text(fp, t, opts), 0);
    rewind(fp);
    n = fread(buf, 1, sizeof(buf) - 1, fp);
    buf[n] = '\0';
    fclose(fp);
    remove(path);
    return buf;
}

static void test_reports(void)
{
    cl_cluster_table_t *t = cl_cluster_table_create();
    cl_report_options_t opts;
    cl_parse_stats_t stats;
    cl_crash_event_t *ev;
    const char *out;

    memset(&stats, 0, sizeof(stats));
    stats.events = 3;
    stats.rejected = 1;
    cl_report_options_default(&opts);
    opts.stats = &stats;
    opts.inputs = 2;

    ev = event("dir/a.log", 1790344991, "parse_header", 1);
    strcpy(ev->thread, "worker \"3\"\t\x01");
    strcpy(ev->process, "bad\xff\xfeutf8 \xc3\xa9");
    cl_cluster_table_add(t, ev, cl_fingerprint(ev, &opts.fp));
    cl_cluster_table_add(t, ev, cl_fingerprint(ev, &opts.fp));
    ev = event("dir/b.log", 0, "other", 0);
    cl_cluster_table_add(t, ev, cl_fingerprint(ev, &opts.fp));

    out = render(0, t, &opts);
    CHECK(out != NULL);
    if (out) {
        CHECK(strstr(out, "2 distinct from 3 crashes") != NULL);
        CHECK(strstr(out, "#1  2 crashes (66.7%)  SIGSEGV") != NULL);
        CHECK(strstr(out, "signature  parse_header|main") != NULL);
        CHECK(strstr(out, "(a.c:10)") != NULL);
        CHECK(strstr(out, "seen       unknown") != NULL);
    }

    out = render(1, t, &opts);
    CHECK(out != NULL);
    if (out) {
        CHECK(strstr(out, "\"signature\": [\"parse_header\", \"main\"]") != NULL);
        CHECK(strstr(out, "\"thread\": \"worker \\\"3\\\"\\t\\u0001\"") != NULL);
        /* Invalid bytes are replaced; valid UTF-8 passes through. */
        CHECK(strstr(out, "\"process\": \"bad\\ufffd\\ufffdutf8 \xc3\xa9\"") != NULL);
        CHECK(strstr(out, "\"first_seen\": \"2026-09-25T14:03:11Z\"") != NULL);
        CHECK(strstr(out, "\"first_seen\": null") != NULL);
    }

    opts.max_clusters = 1;
    out = render(1, t, &opts);
    CHECK(out != NULL && strstr(out, "\"rank\": 2") == NULL);
    cl_cluster_table_destroy(t);
}

static void test_empty_report(void)
{
    cl_cluster_table_t *t = cl_cluster_table_create();
    cl_report_options_t opts;
    const char *out;

    cl_report_options_default(&opts);
    out = render(1, t, &opts);
    CHECK(out != NULL && strstr(out, "\"clusters\": []") != NULL);
    out = render(0, t, &opts);
    CHECK(out != NULL && strstr(out, "0 distinct from 0 crashes") != NULL);
    cl_cluster_table_destroy(t);
}

const test_case_t report_tests[] = {
    { "text_and_json", test_reports },
    { "empty_report", test_empty_report },
    { NULL, NULL },
};
