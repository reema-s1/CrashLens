#define _POSIX_C_SOURCE 200809L

#include "crashlens/parser.h"

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "parser_internal.h"
#include "util.h"

#define READ_CHUNK (64 * 1024)

static const cl_adapter_t *const adapters[] = {
    &cl_native_adapter,
};

typedef enum { ENC_UNKNOWN, ENC_UTF8, ENC_UTF16LE, ENC_UTF16BE } encoding_t;

struct cl_parser {
    cl_log_format_t   format;
    cl_event_cb       cb;
    void             *ctx;
    cl_parse_stats_t  stats;

    /* Per-source state. */
    char              source[CL_SOURCE_MAX];
    unsigned long     line_no;
    int64_t           default_time;
    int               stopped;

    /* Input decoding: the encoding is chosen from the byte-order mark. */
    encoding_t        enc;
    unsigned char     sniff[3];
    size_t            sniff_len;
    unsigned char     odd_byte;   /* first half of a split UTF-16 unit */
    int               have_odd;

    /* Line assembly. */
    char              line[CL_MAX_LINE + 1];
    size_t            line_len;
    int               line_overlong;

    /* The report currently being read, if any. */
    const cl_adapter_t *adapter;
    int               state;
    cl_crash_event_t *ev;
};

cl_parser_t *cl_parser_create(cl_log_format_t fmt, cl_event_cb cb, void *ctx)
{
    cl_parser_t *p = calloc(1, sizeof(*p));

    if (!p)
        return NULL;
    p->ev = malloc(sizeof(*p->ev));
    if (!p->ev) {
        free(p);
        return NULL;
    }
    p->format = fmt;
    p->cb = cb;
    p->ctx = ctx;
    cl_parser_begin(p, "<input>");
    return p;
}

void cl_parser_destroy(cl_parser_t *p)
{
    if (!p)
        return;
    free(p->ev);
    free(p);
}

const cl_parse_stats_t *cl_parser_stats(const cl_parser_t *p)
{
    return &p->stats;
}

void cl_parser_begin(cl_parser_t *p, const char *source)
{
    cl_strlcpy(p->source, source ? source : "<input>", sizeof(p->source));
    p->line_no = 0;
    p->default_time = 0;
    p->stopped = 0;
    p->enc = ENC_UNKNOWN;
    p->sniff_len = 0;
    p->have_odd = 0;
    p->line_len = 0;
    p->line_overlong = 0;
    p->adapter = NULL;
}

static int format_allowed(const cl_parser_t *p, const cl_adapter_t *a)
{
    return p->format == CL_FORMAT_AUTO || p->format == a->format;
}

static void close_report(cl_parser_t *p, int usable)
{
    cl_crash_event_t *ev = p->ev;

    p->adapter = NULL;
    if (!usable || ev->frame_count == 0) {
        p->stats.rejected++;
        return;
    }
    if (ev->timestamp == 0 && p->default_time != 0) {
        ev->timestamp = p->default_time;
        ev->flags |= CL_EVENT_TIME_ESTIMATED;
    }
    p->stats.events++;
    if (ev->flags & CL_EVENT_TRUNCATED)
        p->stats.truncated++;
    if (p->cb && p->cb(ev, p->ctx))
        p->stopped = 1;
}

static const cl_adapter_t *find_starter(const cl_parser_t *p, const char *line)
{
    size_t i;

    for (i = 0; i < CL_ARRAY_LEN(adapters); i++)
        if (format_allowed(p, adapters[i]) && adapters[i]->starts(line))
            return adapters[i];
    return NULL;
}

static void try_begin(cl_parser_t *p, const cl_adapter_t *a, const char *line)
{
    cl_crash_event_t *ev = p->ev;

    cl_event_reset(ev);
    cl_strlcpy(ev->source, p->source, sizeof(ev->source));
    ev->source_line = p->line_no;
    ev->format = a->format;
    p->state = 0;
    if (a->begin(ev, &p->state, line) == 0)
        p->adapter = a;
}

static void handle_line(cl_parser_t *p, const char *line)
{
    const cl_adapter_t *starter = find_starter(p, line);

    if (p->adapter && starter) {
        /* A new report begins before the open one was terminated. */
        p->adapter->eof(p->ev, p->state);
        close_report(p, 1);
    } else if (p->adapter) {
        switch (p->adapter->step(p->ev, &p->state, line)) {
        case CL_STEP_CONTINUE:
            return;
        case CL_STEP_DONE:
            close_report(p, 1);
            return;
        case CL_STEP_INVALID:
            close_report(p, 0);
            return;
        case CL_STEP_DONE_REPLAY:
            close_report(p, 1);
            break;
        case CL_STEP_INVALID_REPLAY:
            close_report(p, 0);
            break;
        }
    }

    if (starter && !p->stopped)
        try_begin(p, starter, line);
}

static void end_line(cl_parser_t *p)
{
    char *line = p->line;
    size_t len = p->line_len;
    char *nul;

    /* Embedded NULs would silently shorten the line for the adapters. */
    while ((nul = memchr(line, '\0', len)) != NULL)
        *nul = ' ';
    while (len > 0 && cl_isspace((unsigned char)line[len - 1]))
        len--;
    line[len] = '\0';

    if (p->line_overlong)
        p->stats.overlong_lines++;
    p->line_len = 0;
    p->line_overlong = 0;
    p->line_no++;
    p->stats.lines++;

    if (!p->stopped)
        handle_line(p, line);
}

static void append(cl_parser_t *p, const char *s, size_t n)
{
    size_t room = CL_MAX_LINE - p->line_len;

    if (n > room) {
        n = room;
        p->line_overlong = 1;
    }
    memcpy(p->line + p->line_len, s, n);
    p->line_len += n;
}

static void decode_utf8(cl_parser_t *p, const unsigned char *d, size_t n)
{
    while (n > 0 && !p->stopped) {
        const unsigned char *nl = memchr(d, '\n', n);
        size_t seg = nl ? (size_t)(nl - d) : n;

        append(p, (const char *)d, seg);
        if (!nl)
            return;
        end_line(p);
        d += seg + 1;
        n -= seg + 1;
    }
}

/* Only the ASCII range matters to the adapters; everything else becomes
 * '?', which keeps UTF-16 logs (common on Windows) parseable. */
static void decode_utf16(cl_parser_t *p, const unsigned char *d, size_t n)
{
    int le = p->enc == ENC_UTF16LE;

    while (n > 0 && !p->stopped) {
        unsigned char b0, b1;
        unsigned unit;
        char c;

        if (p->have_odd) {
            b0 = p->odd_byte;
            b1 = d[0];
            p->have_odd = 0;
            d++;
            n--;
        } else if (n >= 2) {
            b0 = d[0];
            b1 = d[1];
            d += 2;
            n -= 2;
        } else {
            p->odd_byte = d[0];
            p->have_odd = 1;
            return;
        }
        unit = le ? (unsigned)b0 | (unsigned)b1 << 8 : (unsigned)b1 | (unsigned)b0 << 8;
        c = unit < 0x80 ? (char)unit : '?';
        if (c == '\n')
            end_line(p);
        else
            append(p, &c, 1);
    }
}

static void decode(cl_parser_t *p, const unsigned char *d, size_t n)
{
    if (p->enc == ENC_UTF8)
        decode_utf8(p, d, n);
    else
        decode_utf16(p, d, n);
}

static void decide_encoding(cl_parser_t *p)
{
    const unsigned char *s = p->sniff;
    size_t skip = 0;

    p->enc = ENC_UTF8;
    if (p->sniff_len >= 3 && s[0] == 0xEF && s[1] == 0xBB && s[2] == 0xBF) {
        skip = 3;
    } else if (p->sniff_len >= 2 && s[0] == 0xFF && s[1] == 0xFE) {
        p->enc = ENC_UTF16LE;
        skip = 2;
    } else if (p->sniff_len >= 2 && s[0] == 0xFE && s[1] == 0xFF) {
        p->enc = ENC_UTF16BE;
        skip = 2;
    }
    decode(p, s + skip, p->sniff_len - skip);
}

int cl_parser_feed(cl_parser_t *p, const void *data, size_t len)
{
    const unsigned char *d = data;

    if (p->stopped)
        return CL_PARSE_STOPPED;
    p->stats.bytes += len;

    while (p->enc == ENC_UNKNOWN && len > 0) {
        p->sniff[p->sniff_len++] = *d++;
        len--;
        if (p->sniff_len == sizeof(p->sniff))
            decide_encoding(p);
    }
    if (len > 0)
        decode(p, d, len);
    return p->stopped ? CL_PARSE_STOPPED : CL_PARSE_OK;
}

int cl_parser_finish(cl_parser_t *p)
{
    int rc;

    if (p->enc == ENC_UNKNOWN)
        decide_encoding(p);
    if (p->line_len > 0 || p->line_overlong)
        end_line(p);
    if (p->adapter && !p->stopped) {
        p->adapter->eof(p->ev, p->state);
        close_report(p, 1);
    }
    rc = p->stopped ? CL_PARSE_STOPPED : CL_PARSE_OK;
    cl_parser_begin(p, p->source);
    return rc;
}

int cl_parser_parse_buffer(cl_parser_t *p, const char *source,
                           const void *data, size_t len)
{
    cl_parser_begin(p, source);
    cl_parser_feed(p, data, len);
    return cl_parser_finish(p);
}

static int64_t file_mtime(const char *path)
{
    struct stat st;

    if (stat(path, &st) != 0)
        return 0;
    return (int64_t)st.st_mtime;
}

int cl_parser_parse_file(cl_parser_t *p, const char *path)
{
    char *buf;
    FILE *fp;
    size_t n;
    int io_error;
    int rc;

    buf = malloc(READ_CHUNK);
    if (!buf)
        return CL_PARSE_IO;
    fp = fopen(path, "rb");
    if (!fp) {
        free(buf);
        return CL_PARSE_IO;
    }

    cl_parser_begin(p, path);
    p->default_time = file_mtime(path);
    while ((n = fread(buf, 1, READ_CHUNK, fp)) > 0)
        if (cl_parser_feed(p, buf, n) == CL_PARSE_STOPPED)
            break;
    io_error = ferror(fp);
    fclose(fp);
    free(buf);

    rc = cl_parser_finish(p);
    return io_error ? CL_PARSE_IO : rc;
}

int cl_split_file_line(const char *s, const char *end, cl_frame_t *f)
{
    const char *groups[2];
    const char *file_end = end;
    const char *line_end;
    const char *q;
    int64_t line = 0;
    int ngroups = 0;

    /* Accept "file:line" and "file:line:column". */
    while (ngroups < 2) {
        q = file_end;
        while (q > s && cl_isdigit((unsigned char)q[-1]))
            q--;
        if (q == file_end || q - 1 <= s || q[-1] != ':')
            break;
        groups[ngroups++] = q;
        file_end = q - 1;
    }
    if (ngroups == 0)
        return -1;

    /* The line number is the group nearest the file name. */
    line_end = ngroups == 2 ? groups[0] - 1 : end;
    for (q = groups[ngroups - 1]; q < line_end; q++) {
        line = line * 10 + (*q - '0');
        if (line > INT_MAX)
            return -1;
    }

    cl_strlcpyn(f->file, s, (size_t)(file_end - s), sizeof(f->file));
    f->line = (int)line;
    return 0;
}
