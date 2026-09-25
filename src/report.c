#include "crashlens/report.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"

void cl_report_options_default(cl_report_options_t *opts)
{
    memset(opts, 0, sizeof(*opts));
    cl_fp_options_default(&opts->fp);
    opts->max_frames = 12;
}

static size_t shown_clusters(const cl_report_options_t *opts, size_t n)
{
    return opts->max_clusters && opts->max_clusters < n ? opts->max_clusters : n;
}

static double share(uint64_t part, uint64_t total)
{
    return total ? 100.0 * (double)part / (double)total : 0.0;
}

/* ---- text ------------------------------------------------------------ */

static void print_size(FILE *out, uint64_t bytes)
{
    static const char *const units[] = { "B", "KiB", "MiB", "GiB", "TiB" };
    double v = (double)bytes;
    size_t u = 0;

    while (v >= 1024.0 && u + 1 < CL_ARRAY_LEN(units)) {
        v /= 1024.0;
        u++;
    }
    if (u == 0)
        fprintf(out, "%llu B", (unsigned long long)bytes);
    else
        fprintf(out, "%.1f %s", v, units[u]);
}

static void print_frame(FILE *out, const cl_frame_t *f, size_t index, int in_sig)
{
    fprintf(out, "     %c #%-2u ", in_sig ? '*' : ' ', (unsigned)index);
    if (f->flags & CL_FRAME_HAS_ADDRESS)
        fprintf(out, "0x%016llx  ", (unsigned long long)f->address);
    else
        fprintf(out, "%-18s  ", "");

    fputs(f->symbol[0] ? f->symbol : "??", out);
    if (f->symbol[0] && (f->flags & CL_FRAME_HAS_OFFSET) &&
        !(f->flags & CL_FRAME_MODULE_RELATIVE))
        fprintf(out, " + 0x%llx", (unsigned long long)f->offset);

    if (f->flags & CL_FRAME_MODULE_RELATIVE)
        fprintf(out, "  (%s+0x%llx)", cl_basename(f->file),
                (unsigned long long)f->offset);
    else if (f->file[0] && f->line > 0)
        fprintf(out, "  (%s:%d)", f->file, f->line);
    else if (f->file[0])
        fprintf(out, "  (%s)", f->file);
    fputc('\n', out);
}

static void print_cluster(FILE *out, const cl_cluster_t *c, size_t rank,
                          uint64_t total, const cl_report_options_t *opts)
{
    const cl_crash_event_t *ev = c->representative;
    char sig[1024], t1[32], t2[32];
    size_t first, end, i, nframes;

    fprintf(out, "#%u  %llu crash%s (%.1f%%)  %s  fingerprint %016llx\n",
            (unsigned)rank, (unsigned long long)c->count, c->count == 1 ? "" : "es",
            share(c->count, total), ev->kind[0] ? ev->kind : "unknown",
            (unsigned long long)c->fingerprint);

    fputs("    seen       ", out);
    if (c->first_seen == 0) {
        fputs("unknown", out);
    } else {
        cl_format_iso8601(c->first_seen, t1, sizeof(t1));
        cl_format_iso8601(c->last_seen, t2, sizeof(t2));
        if (c->first_seen == c->last_seen)
            fputs(t1, out);
        else
            fprintf(out, "%s .. %s", t1, t2);
    }
    fprintf(out, "  (%u file%s", (unsigned)c->sources, c->sources == 1 ? "" : "s");
    if (c->truncated)
        fprintf(out, ", %llu truncated", (unsigned long long)c->truncated);
    fputs(")\n", out);

    cl_fingerprint_signature(ev, &opts->fp, sig, sizeof(sig));
    fprintf(out, "    signature  %s\n", sig[0] ? sig : "(empty stack)");

    fprintf(out, "    example    %s:%lu", ev->source, ev->source_line);
    if (ev->process[0])
        fprintf(out, "  %s", ev->process);
    if (ev->pid >= 0)
        fprintf(out, "  pid %lld", (long long)ev->pid);
    if (ev->thread[0])
        fprintf(out, "  thread %s", ev->thread);
    fputc('\n', out);

    cl_fingerprint_range(ev, &opts->fp, &first, &end);
    nframes = ev->frame_count;
    if (opts->max_frames && opts->max_frames < nframes)
        nframes = opts->max_frames;
    for (i = 0; i < nframes; i++)
        print_frame(out, &ev->frames[i], i, i >= first && i < end);
    if (nframes < ev->frame_count)
        fprintf(out, "       ... %u more frame%s\n", (unsigned)(ev->frame_count - nframes),
                ev->frame_count - nframes == 1 ? "" : "s");
    else if (ev->flags & CL_EVENT_STACK_TRUNCATED)
        fputs("       ... deeper frames were not recorded\n", out);
}

int cl_report_text(FILE *out, const cl_cluster_table_t *t,
                   const cl_report_options_t *opts)
{
    const cl_parse_stats_t *st = opts->stats;
    const cl_cluster_t **ranked;
    uint64_t total = cl_cluster_table_total(t);
    size_t n, shown, i;

    ranked = cl_cluster_table_ranked(t, &n);
    if (!ranked && n == 0 && cl_cluster_table_size(t) > 0)
        return -1;
    shown = shown_clusters(opts, n);

    fprintf(out, "CrashLens %s triage report\n\n", CRASHLENS_VERSION);
    if (st) {
        fprintf(out, "  inputs     %u file%s", (unsigned)opts->inputs,
                opts->inputs == 1 ? "" : "s");
        if (opts->unreadable)
            fprintf(out, " (%u unreadable)", (unsigned)opts->unreadable);
        fputs(", ", out);
        print_size(out, st->bytes);
        fprintf(out, ", %llu lines\n", (unsigned long long)st->lines);
        fprintf(out, "  crashes    %llu parsed", (unsigned long long)st->events);
        if (st->truncated)
            fprintf(out, " (%llu truncated)", (unsigned long long)st->truncated);
        fprintf(out, ", %llu rejected as unusable\n", (unsigned long long)st->rejected);
    }
    fprintf(out, "  clusters   %u distinct from %llu crash%s", (unsigned)n,
            (unsigned long long)total, total == 1 ? "" : "es");
    if (opts->fp.top_n > 0)
        fprintf(out, ", top %d frames", opts->fp.top_n);
    else
        fputs(", whole stack", out);
    fputs(opts->fp.skip_noise ? ", crash-handler frames skipped\n" : "\n", out);
    if (shown < n)
        fprintf(out, "  showing    top %u\n", (unsigned)shown);

    for (i = 0; i < shown; i++) {
        fputc('\n', out);
        print_cluster(out, ranked[i], i + 1, total, opts);
    }
    free(ranked);
    return ferror(out) ? -1 : 0;
}

/* ---- JSON ------------------------------------------------------------ */

/* Length of the well-formed UTF-8 sequence at p, or 0. */
static size_t utf8_sequence(const unsigned char *p)
{
    uint32_t cp;
    size_t n, i;

    if (p[0] >= 0xC2 && p[0] <= 0xDF) {
        n = 2;
        cp = p[0] & 0x1Fu;
    } else if (p[0] >= 0xE0 && p[0] <= 0xEF) {
        n = 3;
        cp = p[0] & 0x0Fu;
    } else if (p[0] >= 0xF0 && p[0] <= 0xF4) {
        n = 4;
        cp = p[0] & 0x07u;
    } else {
        return 0;
    }
    /* The terminating NUL fails the continuation test, so this never
     * reads past the end of the string. */
    for (i = 1; i < n; i++) {
        if ((p[i] & 0xC0) != 0x80)
            return 0;
        cp = cp << 6 | (p[i] & 0x3Fu);
    }
    if ((n == 3 && (cp < 0x800 || (cp >= 0xD800 && cp <= 0xDFFF))) ||
        (n == 4 && (cp < 0x10000 || cp > 0x10FFFF)))
        return 0;
    return n;
}

static void json_string(FILE *out, const char *s)
{
    const unsigned char *p = (const unsigned char *)s;

    fputc('"', out);
    while (*p) {
        size_t n;

        if (*p == '"' || *p == '\\') {
            fputc('\\', out);
            fputc(*p++, out);
        } else if (*p == '\n') {
            fputs("\\n", out);
            p++;
        } else if (*p == '\t') {
            fputs("\\t", out);
            p++;
        } else if (*p < 0x20) {
            fprintf(out, "\\u%04x", *p++);
        } else if (*p < 0x80) {
            fputc(*p++, out);
        } else if ((n = utf8_sequence(p)) != 0) {
            fwrite(p, 1, n, out);
            p += n;
        } else {
            fputs("\\ufffd", out);
            p++;
        }
    }
    fputc('"', out);
}

static void json_opt_string(FILE *out, const char *s)
{
    if (s[0])
        json_string(out, s);
    else
        fputs("null", out);
}

static void json_time(FILE *out, int64_t t)
{
    char buf[32];

    if (t == 0) {
        fputs("null", out);
        return;
    }
    cl_format_iso8601(t, buf, sizeof(buf));
    json_string(out, buf);
}

static void json_frame(FILE *out, const cl_frame_t *f, size_t index, int in_sig)
{
    fprintf(out, "{\"index\": %u, \"address\": ", (unsigned)index);
    if (f->flags & CL_FRAME_HAS_ADDRESS)
        fprintf(out, "\"0x%llx\"", (unsigned long long)f->address);
    else
        fputs("null", out);
    fputs(", \"symbol\": ", out);
    json_opt_string(out, f->symbol);
    fputs(", \"offset\": ", out);
    if (f->flags & CL_FRAME_HAS_OFFSET)
        fprintf(out, "\"0x%llx\"", (unsigned long long)f->offset);
    else
        fputs("null", out);
    fputs(f->flags & CL_FRAME_MODULE_RELATIVE ? ", \"module\": " : ", \"file\": ", out);
    json_opt_string(out, f->file);
    fputs(", \"line\": ", out);
    if (f->line > 0)
        fprintf(out, "%d", f->line);
    else
        fputs("null", out);
    fprintf(out, ", \"symbolicated\": %s, \"in_signature\": %s}",
            f->flags & CL_FRAME_SYMBOLICATED ? "true" : "false",
            in_sig ? "true" : "false");
}

static void json_cluster(FILE *out, const cl_cluster_t *c, size_t rank,
                         uint64_t total, const cl_report_options_t *opts)
{
    const cl_crash_event_t *ev = c->representative;
    char token[CL_TOKEN_MAX];
    size_t first, end, i, nframes;

    fprintf(out, "    {\n      \"rank\": %u,\n      \"fingerprint\": \"%016llx\",\n",
            (unsigned)rank, (unsigned long long)c->fingerprint);
    fprintf(out, "      \"count\": %llu,\n      \"share\": %.4f,\n",
            (unsigned long long)c->count, share(c->count, total) / 100.0);
    fprintf(out, "      \"truncated\": %llu,\n      \"kind\": ",
            (unsigned long long)c->truncated);
    json_opt_string(out, ev->kind);
    fputs(",\n      \"signal\": ", out);
    if (ev->signal)
        fprintf(out, "%d", ev->signal);
    else
        fputs("null", out);
    fputs(",\n      \"first_seen\": ", out);
    json_time(out, c->first_seen);
    fputs(",\n      \"last_seen\": ", out);
    json_time(out, c->last_seen);
    fprintf(out, ",\n      \"sources\": %u,\n      \"signature\": [", (unsigned)c->sources);

    cl_fingerprint_range(ev, &opts->fp, &first, &end);
    for (i = first; i < end; i++) {
        cl_frame_token(&ev->frames[i], token, sizeof(token));
        if (i > first)
            fputs(", ", out);
        json_string(out, token);
    }

    fputs("],\n      \"example\": {\n        \"source\": ", out);
    json_string(out, ev->source);
    fprintf(out, ",\n        \"line\": %lu,\n        \"format\": \"%s\",\n",
            ev->source_line, cl_format_name(ev->format));
    fputs("        \"process\": ", out);
    json_opt_string(out, ev->process);
    fputs(",\n        \"pid\": ", out);
    if (ev->pid >= 0)
        fprintf(out, "%lld", (long long)ev->pid);
    else
        fputs("null", out);
    fputs(",\n        \"thread\": ", out);
    json_opt_string(out, ev->thread);
    fputs(",\n        \"timestamp\": ", out);
    json_time(out, ev->timestamp);
    fprintf(out, ",\n        \"truncated\": %s,\n        \"frames\": [",
            ev->flags & CL_EVENT_TRUNCATED ? "true" : "false");

    nframes = ev->frame_count;
    if (opts->max_frames && opts->max_frames < nframes)
        nframes = opts->max_frames;
    for (i = 0; i < nframes; i++) {
        fputs(i ? ",\n          " : "\n          ", out);
        json_frame(out, &ev->frames[i], i, i >= first && i < end);
    }
    fprintf(out, "%s],\n        \"frames_omitted\": %u\n      }\n    }",
            nframes ? "\n        " : "", (unsigned)(ev->frame_count - nframes));
}

int cl_report_json(FILE *out, const cl_cluster_table_t *t,
                   const cl_report_options_t *opts)
{
    const cl_parse_stats_t *st = opts->stats;
    const cl_cluster_t **ranked;
    uint64_t total = cl_cluster_table_total(t);
    size_t n, shown, i;

    ranked = cl_cluster_table_ranked(t, &n);
    if (!ranked && n == 0 && cl_cluster_table_size(t) > 0)
        return -1;
    shown = shown_clusters(opts, n);

    fprintf(out, "{\n  \"version\": \"%s\",\n", CRASHLENS_VERSION);
    fprintf(out, "  \"options\": {\"top_frames\": %d, \"skip_noise\": %s},\n",
            opts->fp.top_n > 0 ? opts->fp.top_n : 0,
            opts->fp.skip_noise ? "true" : "false");
    fprintf(out, "  \"summary\": {\"inputs\": %u, \"unreadable\": %u",
            (unsigned)opts->inputs, (unsigned)opts->unreadable);
    if (st)
        fprintf(out, ", \"bytes\": %llu, \"lines\": %llu, \"parsed\": %llu, "
                     "\"truncated\": %llu, \"rejected\": %llu",
                (unsigned long long)st->bytes, (unsigned long long)st->lines,
                (unsigned long long)st->events, (unsigned long long)st->truncated,
                (unsigned long long)st->rejected);
    fprintf(out, ", \"crashes\": %llu, \"clusters\": %u},\n  \"clusters\": [",
            (unsigned long long)total, (unsigned)n);

    for (i = 0; i < shown; i++) {
        fputs(i ? ",\n" : "\n", out);
        json_cluster(out, ranked[i], i + 1, total, opts);
    }
    fputs(shown ? "\n  ]\n}\n" : "]\n}\n", out);
    free(ranked);
    return ferror(out) ? -1 : 0;
}
