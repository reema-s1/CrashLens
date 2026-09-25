/* Scale benchmark: synthesises a large log set from a known number of
 * bugs, then measures parse throughput and how well different
 * fingerprinting strategies recover the injected bugs.
 *
 * Each bug is a fixed 5-frame call path at the top of the stack. Every
 * crash of that bug varies in everything that should not matter: PID,
 * thread, timestamp, ASLR slide, instruction offsets, the callers deeper
 * in the stack, crash-handler frames on top, compiler clone suffixes and
 * report format (native or sanitizer). Some bug pairs share their first
 * three or four frames, so over-merging shows up too. Ordinary log lines,
 * truncated reports and reports with no usable stack are interleaved.
 *
 *   scale_bench [--events N] [--bugs K] [--seed S] [--repeat R] [--check]
 */

#if !defined(_WIN32)
#define _POSIX_C_SOURCE 199309L
#endif

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <time.h>
#endif

#include "crashlens/cluster.h"
#include "crashlens/fingerprint.h"
#include "crashlens/parser.h"

#define CORE_FRAMES   5
#define MAX_TAIL      20
#define MAX_BUGS      4096

/* ---- utilities -------------------------------------------------------- */

static double now_seconds(void)
{
#ifdef _WIN32
    LARGE_INTEGER freq, t;

    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t);
    return (double)t.QuadPart / (double)freq.QuadPart;
#else
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
#endif
}

static uint64_t rng_state;

static uint64_t rnd(void)
{
    uint64_t x = rng_state;

    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    rng_state = x;
    return x * 0x2545F4914F6CDD1Dull;
}

static unsigned below(unsigned n)
{
    return (unsigned)(rnd() % n);
}

static int chance(unsigned percent)
{
    return below(100) < percent;
}

typedef struct {
    char  *data;
    size_t len;
    size_t cap;
} buffer_t;

#if defined(__GNUC__)
static void append(buffer_t *b, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
#endif

static void append(buffer_t *b, const char *fmt, ...)
{
    va_list ap;
    int n;

    for (;;) {
        size_t room = b->cap - b->len;

        va_start(ap, fmt);
        n = vsnprintf(b->data + b->len, room, fmt, ap);
        va_end(ap);
        if (n < 0) {
            fputs("scale_bench: formatting failed\n", stderr);
            exit(2);
        }
        if ((size_t)n < room) {
            b->len += (size_t)n;
            return;
        }
        b->cap = b->cap * 2 + (size_t)n + 4096;
        b->data = realloc(b->data, b->cap);
        if (!b->data) {
            fputs("scale_bench: out of memory\n", stderr);
            exit(2);
        }
    }
}

/* ---- synthetic bugs ------------------------------------------------- */

static const char *const subsystems[] = {
    "codec", "segment", "index", "net", "cache", "sched", "io", "crypto", "json",
    "http", "store", "fs", "audio", "render", "sync", "journal", "plugin", "vm",
};
static const char *const verbs[] = {
    "read", "write", "decode", "encode", "flush", "lookup", "insert", "resize",
    "parse", "validate", "commit", "load", "drain", "merge", "split",
};
static const char *const nouns[] = {
    "header", "block", "entry", "frame", "page", "node", "buffer", "table",
    "record", "chunk",
};

#define POOL_SIZE (sizeof(subsystems) / sizeof(subsystems[0]) * \
                   sizeof(verbs) / sizeof(verbs[0]) * sizeof(nouns) / sizeof(nouns[0]))

static char pool[POOL_SIZE][48];

static void build_pool(void)
{
    size_t s, v, n, k = 0;

    for (s = 0; s < sizeof(subsystems) / sizeof(subsystems[0]); s++)
        for (v = 0; v < sizeof(verbs) / sizeof(verbs[0]); v++)
            for (n = 0; n < sizeof(nouns) / sizeof(nouns[0]); n++)
                snprintf(pool[k++], sizeof(pool[0]), "%s_%s_%s", subsystems[s], verbs[v],
                         nouns[n]);
}

static const char *const native_kinds[] = { "SIGSEGV", "SIGBUS", "SIGFPE", "SIGILL" };
static const char *const sanitizer_kinds[] = {
    "heap-use-after-free", "heap-buffer-overflow", "stack-buffer-overflow", "SEGV",
};

/* Frames a crash handler or runtime adds above the faulting function. */
static const char *const abort_noise[] = { "__pthread_kill_implementation", "raise",
                                           "abort", "__assert_fail" };

typedef struct {
    unsigned core[CORE_FRAMES];   /* pool indices, top of stack first */
    unsigned tail[MAX_TAIL];      /* usual callers below the core */
    unsigned tail_len;
    int      aborts;              /* crashes via assert()/abort() */
    unsigned kind;
} bug_t;

static int same_core(const bug_t *a, const bug_t *b)
{
    return memcmp(a->core, b->core, sizeof(a->core)) == 0;
}

static void make_bugs(bug_t *bugs, unsigned nbugs)
{
    unsigned i, j, k;

    for (i = 0; i < nbugs; i++) {
        bug_t *b = &bugs[i];
        int unique;

        do {
            if (i % 2 == 1 && chance(70)) {
                /* A near-duplicate of the previous bug: same first three or
                 * four frames, then a different call path. */
                unsigned shared = 3 + below(2);

                *b = bugs[i - 1];
                for (k = shared; k < CORE_FRAMES; k++)
                    b->core[k] = below((unsigned)POOL_SIZE);
            } else {
                for (k = 0; k < CORE_FRAMES; k++)
                    b->core[k] = below((unsigned)POOL_SIZE);
            }
            unique = 1;
            for (j = 0; j < i && unique; j++)
                unique = !same_core(b, &bugs[j]);
        } while (!unique);

        b->tail_len = 2 + below(MAX_TAIL - 2);
        for (k = 0; k < b->tail_len; k++)
            b->tail[k] = below((unsigned)POOL_SIZE);
        b->aborts = chance(25);
        b->kind = below(4);
    }
}

/* Crash counts per bug follow a rough power law, as in real crash data. */
static unsigned pick_bug(unsigned nbugs)
{
    unsigned b = (unsigned)((double)nbugs * ((double)below(1000) / 1000.0) *
                            ((double)below(1000) / 1000.0));

    return b < nbugs ? b : nbugs - 1;
}

static uint64_t function_address(unsigned pool_index)
{
    return 0x1000 + (uint64_t)pool_index * 0x400;
}

typedef struct {
    const char *name;
    uint64_t    address;
    uint64_t    offset;
    int         line;
} gen_frame_t;

static unsigned event_stack(const bug_t *bug, int sanitizer, gen_frame_t *out)
{
    static char clone_name[64];
    uint64_t slide = ((uint64_t)0x55 << 40) + ((uint64_t)below(1u << 20) << 12);
    unsigned n = 0, k;

    if (bug->aborts && !sanitizer) {
        for (k = 0; k < 4; k++) {
            out[n].name = abort_noise[k];
            out[n].address = 0x7f0000000000ull + slide + k * 0x100;
            out[n].offset = 16 + k;
            out[n].line = 0;
            n++;
        }
    } else if (sanitizer && chance(30)) {
        out[n].name = "__asan_report_load4";
        out[n].address = 0x7f0000100000ull + slide;
        out[n].offset = 12;
        out[n].line = 0;
        n++;
    }

    for (k = 0; k < CORE_FRAMES; k++) {
        out[n].name = pool[bug->core[k]];
        if (k == 1 && chance(10)) {
            snprintf(clone_name, sizeof(clone_name), "%s.isra.0", pool[bug->core[k]]);
            out[n].name = clone_name;
        }
        out[n].offset = 8 + below(0x80);
        out[n].address = slide + function_address(bug->core[k]) + out[n].offset;
        out[n].line = 10 + (int)(bug->core[k] % 400);
        n++;
    }

    /* Half the crashes arrive through a different caller chain. */
    if (chance(50)) {
        unsigned depth = 1 + below(MAX_TAIL);

        for (k = 0; k < depth; k++) {
            unsigned f = below((unsigned)POOL_SIZE);

            out[n].name = chance(10) ? NULL : pool[f];
            out[n].offset = below(0x200);
            out[n].address = slide + function_address(f) + out[n].offset;
            out[n].line = 0;
            n++;
        }
    } else {
        for (k = 0; k < bug->tail_len; k++) {
            out[n].name = pool[bug->tail[k]];
            out[n].offset = below(0x200);
            out[n].address = slide + function_address(bug->tail[k]) + out[n].offset;
            out[n].line = 0;
            n++;
        }
    }
    return n;
}

static void write_native(buffer_t *b, const bug_t *bug, int64_t ts, int truncate)
{
    gen_frame_t frames[64];
    unsigned n = event_stack(bug, 0, frames), k;

    append(b, "=== CRASH ===\nTime: %04d-%02d-%02dT%02d:%02d:%02dZ\n", 2026, 9,
           1 + (int)(ts / 86400), (int)(ts / 3600 % 24), (int)(ts / 60 % 60), (int)(ts % 60));
    append(b, "Process: indexer [%u]\nThread: worker-%u\n", 1000 + below(60000), below(16));
    append(b, "Signal: %s\nBacktrace:\n", bug->aborts ? "SIGABRT" : native_kinds[bug->kind]);
    for (k = 0; k < n; k++) {
        append(b, "  #%u  0x%016llx %s + %llu", k, (unsigned long long)frames[k].address,
               frames[k].name ? frames[k].name : "??", (unsigned long long)frames[k].offset);
        if (frames[k].line)
            append(b, " (src/%s.c:%d)", frames[k].name, frames[k].line);
        append(b, "\n");
    }
    if (!truncate)
        append(b, "=== END ===\n");
}

static void write_sanitizer(buffer_t *b, const bug_t *bug)
{
    gen_frame_t frames[64];
    unsigned n = event_stack(bug, 1, frames), k;

    append(b, "=================================================================\n");
    append(b, "==%u==ERROR: AddressSanitizer: %s on address 0x602000000010\n",
           1000 + below(60000), sanitizer_kinds[bug->kind]);
    append(b, "READ of size 4 at 0x602000000010 thread T%u\n", below(16));
    for (k = 0; k < n; k++) {
        if (frames[k].name)
            append(b, "    #%u 0x%llx in %s", k, (unsigned long long)frames[k].address,
                   frames[k].name);
        else
            append(b, "    #%u 0x%llx (/opt/indexer/bin/indexer+0x%llx)", k,
                   (unsigned long long)frames[k].address,
                   (unsigned long long)(frames[k].address & 0xfffff));
        if (frames[k].name && frames[k].line)
            append(b, " /src/indexer/%s.c:%d:%u", frames[k].name, frames[k].line, below(40));
        append(b, "\n");
    }
    append(b, "\nSUMMARY: AddressSanitizer: %s\n==1==ABORTING\n", sanitizer_kinds[bug->kind]);
}

static void write_log_noise(buffer_t *b)
{
    static const char *const msgs[] = {
        "INFO request served, ms=", "DEBUG cache hit ratio, percent=",
        "WARN retrying segment", "INFO compaction freed pages, count=",
    };
    const char *msg = msgs[below(4)];

    append(b, "2026-09-01T12:00:00Z %s %u\n", msg, below(1000));
}

/* ---- evaluation ----------------------------------------------------- */

enum { STRATEGY_RAW, STRATEGY_WHOLE, STRATEGY_TOP_KEEP_NOISE, STRATEGY_DEFAULT, NSTRATEGIES };

static const char *const strategy_names[NSTRATEGIES] = {
    "raw frames (address + symbol)",
    "function names, whole stack",
    "top 5 names, noise kept",
    "top 5 names, noise skipped",
};

typedef struct {
    uint64_t key;
    uint32_t label;
    uint32_t pure;
} sample_t;

typedef struct {
    size_t  clusters;
    double  purity;        /* fraction of crashes in a cluster's majority bug */
    double  completeness;  /* fraction of crashes in their bug's largest cluster */
    size_t  exact;         /* bugs recovered as exactly one cluster */
} metrics_t;

static int by_key(const void *pa, const void *pb)
{
    const sample_t *a = pa, *b = pb;

    if (a->key != b->key)
        return a->key < b->key ? -1 : 1;
    return a->label < b->label ? -1 : a->label > b->label;
}

static int by_label(const void *pa, const void *pb)
{
    const sample_t *a = pa, *b = pb;

    if (a->label != b->label)
        return a->label < b->label ? -1 : 1;
    return a->key < b->key ? -1 : a->key > b->key;
}

static metrics_t evaluate(sample_t *s, size_t n)
{
    metrics_t m = { 0, 0.0, 0.0, 0 };
    size_t i, j, majority = 0, largest = 0;

    if (n == 0)
        return m;

    qsort(s, n, sizeof(*s), by_key);
    for (i = 0; i < n; i = j) {
        size_t best = 0, run = 0, labels = 0;

        for (j = i; j < n && s[j].key == s[i].key; j++) {
            if (j == i || s[j].label != s[j - 1].label) {
                run = 0;
                labels++;
            }
            if (++run > best)
                best = run;
        }
        for (run = i; run < j; run++)
            s[run].pure = labels == 1;
        majority += best;
        m.clusters++;
    }

    qsort(s, n, sizeof(*s), by_label);
    for (i = 0; i < n; i = j) {
        size_t best = 0, run = 0, keys = 0;

        for (j = i; j < n && s[j].label == s[i].label; j++) {
            if (j == i || s[j].key != s[j - 1].key) {
                run = 0;
                keys++;
            }
            if (++run > best)
                best = run;
        }
        largest += best;
        if (keys == 1 && s[i].pure)
            m.exact++;
    }

    m.purity = (double)majority / (double)n;
    m.completeness = (double)largest / (double)n;
    return m;
}

typedef struct {
    const uint32_t  *labels;       /* expected bug per accepted event */
    size_t           nlabels;
    size_t           seen;
    sample_t        *samples[NSTRATEGIES];
    cl_fp_options_t  fp[NSTRATEGIES];
    cl_cluster_table_t *clusters;  /* timing runs only */
} run_ctx_t;

static uint64_t raw_key(const cl_crash_event_t *ev)
{
    uint64_t h = CL_FNV1A64_INIT;
    size_t i;

    for (i = 0; i < ev->frame_count; i++) {
        h = cl_fnv1a64(&ev->frames[i].address, sizeof(ev->frames[i].address), h);
        h = cl_fnv1a64(ev->frames[i].symbol, strlen(ev->frames[i].symbol), h);
    }
    return h;
}

static int on_event_evaluate(cl_crash_event_t *ev, void *arg)
{
    run_ctx_t *c = arg;
    uint32_t label;
    int s;

    if (c->seen >= c->nlabels) {
        c->seen++;
        return 0;
    }
    label = c->labels[c->seen];
    for (s = 0; s < NSTRATEGIES; s++) {
        sample_t *smp = &c->samples[s][c->seen];

        smp->key = s == STRATEGY_RAW ? raw_key(ev) : cl_fingerprint(ev, &c->fp[s]);
        smp->label = label;
    }
    c->seen++;
    return 0;
}

static int on_event_timed(cl_crash_event_t *ev, void *arg)
{
    run_ctx_t *c = arg;

    return cl_cluster_table_add(c->clusters, ev,
                                cl_fingerprint(ev, &c->fp[STRATEGY_DEFAULT])) != 0;
}

/* ---- main ----------------------------------------------------------- */

static unsigned long parse_arg(const char *s, unsigned long max)
{
    char *end;
    unsigned long v = strtoul(s, &end, 10);

    if (*s == '\0' || *end != '\0' || v == 0 || v > max) {
        fprintf(stderr, "scale_bench: bad number '%s'\n", s);
        exit(2);
    }
    return v;
}

int main(int argc, char **argv)
{
    unsigned long nevents = 50000, nbugs = 40, seed = 1, repeat = 3, i;
    int check = 0, a, s;
    buffer_t buf = { NULL, 0, 0 };
    bug_t *bugs;
    uint32_t *labels;
    size_t nlabels = 0, malformed = 0, truncated = 0;
    run_ctx_t ctx;
    cl_parser_t *p;
    const cl_parse_stats_t *st;
    double best = 0.0, t0;
    metrics_t results[NSTRATEGIES];

    for (a = 1; a < argc; a++) {
        if (strcmp(argv[a], "--events") == 0 && a + 1 < argc)
            nevents = parse_arg(argv[++a], 10000000);
        else if (strcmp(argv[a], "--bugs") == 0 && a + 1 < argc)
            nbugs = parse_arg(argv[++a], MAX_BUGS);
        else if (strcmp(argv[a], "--seed") == 0 && a + 1 < argc)
            seed = parse_arg(argv[++a], 0xffffffffUL);
        else if (strcmp(argv[a], "--repeat") == 0 && a + 1 < argc)
            repeat = parse_arg(argv[++a], 100);
        else if (strcmp(argv[a], "--check") == 0)
            check = 1;
        else {
            fprintf(stderr, "usage: scale_bench [--events N] [--bugs K] [--seed S] "
                            "[--repeat R] [--check]\n");
            return 2;
        }
    }

    rng_state = 0x9E3779B97F4A7C15ull * (seed + 1);
    build_pool();
    bugs = malloc(nbugs * sizeof(*bugs));
    labels = malloc(nevents * sizeof(*labels));
    if (!bugs || !labels)
        return 2;
    make_bugs(bugs, (unsigned)nbugs);

    /* Generate. */
    for (i = 0; i < nevents; i++) {
        unsigned b = pick_bug((unsigned)nbugs);
        int64_t ts = (int64_t)below(7 * 86400);
        unsigned noise = below(4);

        while (noise--)
            write_log_noise(&buf);

        if (chance(2)) {
            /* Starts like a crash but never provides a stack. */
            append(&buf, "=== CRASH ===\nSignal: SIGSEGV\nBacktrace:\n<stack unavailable>\n"
                         "=== END ===\n");
            malformed++;
            continue;
        }
        if (chance(35)) {
            write_sanitizer(&buf, &bugs[b]);
        } else {
            int cut = chance(1);

            write_native(&buf, &bugs[b], ts, cut);
            if (cut) {
                truncated++;
                append(&buf, "\n");
            }
        }
        labels[nlabels++] = b;
    }

    /* Accuracy of each strategy over one parse. */
    memset(&ctx, 0, sizeof(ctx));
    ctx.labels = labels;
    ctx.nlabels = nlabels;
    for (s = 0; s < NSTRATEGIES; s++) {
        cl_fp_options_default(&ctx.fp[s]);
        ctx.samples[s] = malloc((nlabels ? nlabels : 1) * sizeof(sample_t));
        if (!ctx.samples[s])
            return 2;
    }
    ctx.fp[STRATEGY_WHOLE].top_n = 0;
    ctx.fp[STRATEGY_TOP_KEEP_NOISE].skip_noise = 0;

    p = cl_parser_create(CL_FORMAT_AUTO, on_event_evaluate, &ctx);
    cl_parser_parse_buffer(p, "synthetic", buf.data, buf.len);
    st = cl_parser_stats(p);
    if (ctx.seen != nlabels || st->rejected != malformed) {
        fprintf(stderr, "scale_bench: parsed %lu crashes and rejected %llu, expected %lu and %lu\n",
                (unsigned long)ctx.seen, (unsigned long long)st->rejected,
                (unsigned long)nlabels, (unsigned long)malformed);
        return 1;
    }
    for (s = 0; s < NSTRATEGIES; s++)
        results[s] = evaluate(ctx.samples[s], nlabels);

    printf("CrashLens scale benchmark\n\n");
    printf("  input        %.1f MiB, %llu lines, %lu crash reports from %lu bugs (seed %lu)\n",
           (double)buf.len / (1024.0 * 1024.0), (unsigned long long)st->lines, nevents, nbugs,
           seed);
    printf("  malformed    %lu without a stack (rejected), %lu truncated (kept)\n",
           (unsigned long)malformed, (unsigned long)truncated);
    cl_parser_destroy(p);

    /* Throughput of the default pipeline: parse, fingerprint, cluster. */
    for (i = 0; i < repeat; i++) {
        double elapsed;

        ctx.clusters = cl_cluster_table_create();
        p = cl_parser_create(CL_FORMAT_AUTO, on_event_timed, &ctx);
        t0 = now_seconds();
        cl_parser_parse_buffer(p, "synthetic", buf.data, buf.len);
        elapsed = now_seconds() - t0;
        if (best == 0.0 || elapsed < best)
            best = elapsed;
        cl_parser_destroy(p);
        cl_cluster_table_destroy(ctx.clusters);
    }
    if (best <= 0.0)
        best = 1e-9;
    printf("  throughput   %.1f MiB/s, %.0f crashes/s (parse + fingerprint + cluster, "
           "best of %lu)\n\n", (double)buf.len / (1024.0 * 1024.0) / best,
           (double)nlabels / best, repeat);

    printf("  %-32s %9s %8s %13s %11s\n", "fingerprint", "clusters", "purity", "completeness",
           "exact bugs");
    for (s = 0; s < NSTRATEGIES; s++)
        printf("  %-32s %9lu %8.3f %13.3f %7lu/%-3lu\n", strategy_names[s],
               (unsigned long)results[s].clusters, results[s].purity,
               results[s].completeness, (unsigned long)results[s].exact, nbugs);

    for (s = 0; s < NSTRATEGIES; s++)
        free(ctx.samples[s]);
    free(labels);
    free(bugs);
    free(buf.data);

    if (check) {
        const metrics_t *d = &results[STRATEGY_DEFAULT];

        /* Every bug that crashed at least once must come back as exactly
         * one pure cluster. */
        if (d->purity < 1.0 || d->completeness < 1.0 || d->exact != d->clusters) {
            fputs("scale_bench: default fingerprint did not recover the injected bugs\n",
                  stderr);
            return 1;
        }
    }
    return 0;
}
