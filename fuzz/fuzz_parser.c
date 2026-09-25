/* Fuzz target: the whole pipeline on arbitrary bytes.
 *
 * Besides "does not crash or leak", it checks invariants that only hold
 * if parsing is independent of how the input is chunked and if every
 * event handed out is internally consistent. */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crashlens/cluster.h"
#include "crashlens/fingerprint.h"
#include "crashlens/parser.h"
#include "crashlens/report.h"

#ifdef _WIN32
#define NULL_DEVICE "NUL"
#else
#define NULL_DEVICE "/dev/null"
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

typedef struct {
    cl_cluster_table_t *clusters;
    cl_fp_options_t     fp;
} fuzz_ctx_t;

static void check(int ok, const char *what)
{
    if (!ok) {
        fprintf(stderr, "invariant violated: %s\n", what);
        abort();
    }
}

static void check_terminated(const char *field, size_t size, const char *what)
{
    check(memchr(field, '\0', size) != NULL, what);
}

static int on_event(cl_crash_event_t *ev, void *arg)
{
    fuzz_ctx_t *ctx = arg;
    char sig[512];
    size_t i, len;
    uint64_t fp;

    check(ev->frame_count > 0 && ev->frame_count <= CL_MAX_STACK_DEPTH, "frame count");
    check_terminated(ev->kind, sizeof(ev->kind), "kind terminated");
    check_terminated(ev->process, sizeof(ev->process), "process terminated");
    check_terminated(ev->thread, sizeof(ev->thread), "thread terminated");
    check_terminated(ev->source, sizeof(ev->source), "source terminated");
    for (i = 0; i < ev->frame_count; i++) {
        check_terminated(ev->frames[i].symbol, sizeof(ev->frames[i].symbol), "symbol");
        check_terminated(ev->frames[i].file, sizeof(ev->frames[i].file), "file");
        check(ev->frames[i].line >= 0, "line number");
    }

    fp = cl_fingerprint(ev, &ctx->fp);
    len = cl_fingerprint_signature(ev, &ctx->fp, sig, sizeof(sig));
    if (len < sizeof(sig))
        check(fp == cl_fnv1a64(sig, len, CL_FNV1A64_INIT), "fingerprint matches signature");

    cl_cluster_table_add(ctx->clusters, ev, fp);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static FILE *sink;
    fuzz_ctx_t ctx;
    cl_report_options_t ropts;
    cl_parse_stats_t once;
    const cl_parse_stats_t *st;
    cl_parser_t *p;
    size_t off = 0, step = 1 + size % 61;

    if (!sink)
        sink = fopen(NULL_DEVICE, "w");

    ctx.clusters = cl_cluster_table_create();
    cl_fp_options_default(&ctx.fp);
    ctx.fp.top_n = (int)(size % 7);          /* includes 0 = whole stack */
    ctx.fp.skip_noise = size % 2 == 0;
    p = cl_parser_create(CL_FORMAT_AUTO, on_event, &ctx);
    if (!ctx.clusters || !p)
        abort();

    cl_parser_parse_buffer(p, "fuzz", data, size);
    once = *cl_parser_stats(p);

    /* Same input in uneven chunks must give the same result. */
    cl_parser_begin(p, "fuzz");
    while (off < size) {
        size_t n = step < size - off ? step : size - off;

        cl_parser_feed(p, data + off, n);
        off += n;
        step = step * 7 % 61 + 1;
    }
    cl_parser_finish(p);
    st = cl_parser_stats(p);
    check(st->events == 2 * once.events, "chunked parse: events");
    check(st->rejected == 2 * once.rejected, "chunked parse: rejected");
    check(st->lines == 2 * once.lines, "chunked parse: lines");
    check(st->truncated == 2 * once.truncated, "chunked parse: truncated");
    check(cl_cluster_table_total(ctx.clusters) == st->events, "every event clustered");

    if (sink) {
        cl_report_options_default(&ropts);
        ropts.fp = ctx.fp;
        ropts.stats = st;
        cl_report_text(sink, ctx.clusters, &ropts);
        cl_report_json(sink, ctx.clusters, &ropts);
    }

    cl_parser_destroy(p);
    cl_cluster_table_destroy(ctx.clusters);
    return 0;
}
