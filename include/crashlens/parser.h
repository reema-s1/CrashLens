#ifndef CRASHLENS_PARSER_H
#define CRASHLENS_PARSER_H

#include <stddef.h>
#include <stdint.h>

#include "crashlens/crash_event.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Longest line handed to a format adapter; longer lines are cut here. */
#define CL_MAX_LINE 4096

typedef struct cl_parser cl_parser_t;

/* Called once per accepted crash event. The event is owned by the parser
 * and only valid for the duration of the call, but may be modified (e.g.
 * symbolicated) in place. Return nonzero to stop parsing. */
typedef int (*cl_event_cb)(cl_crash_event_t *ev, void *ctx);

typedef struct {
    uint64_t bytes;
    uint64_t lines;
    uint64_t events;          /* crash events delivered to the callback */
    uint64_t truncated;       /* ...of which were missing their terminator */
    uint64_t rejected;        /* reports that started but were unusable */
    uint64_t overlong_lines;  /* lines cut at CL_MAX_LINE */
} cl_parse_stats_t;

/* Return values of the feed/finish/parse functions. */
enum {
    CL_PARSE_OK      = 0,
    CL_PARSE_STOPPED = 1,  /* the callback asked to stop */
    CL_PARSE_IO      = -1  /* input could not be read */
};

cl_parser_t *cl_parser_create(cl_log_format_t fmt, cl_event_cb cb, void *ctx);
void         cl_parser_destroy(cl_parser_t *p);

/* Streaming interface: begin a named source, feed it in arbitrary chunks,
 * then finish it to flush the last line and any open event. */
void cl_parser_begin(cl_parser_t *p, const char *source);
int  cl_parser_feed(cl_parser_t *p, const void *data, size_t len);
int  cl_parser_finish(cl_parser_t *p);

/* Convenience wrappers around begin/feed/finish. */
int cl_parser_parse_buffer(cl_parser_t *p, const char *source,
                           const void *data, size_t len);
int cl_parser_parse_file(cl_parser_t *p, const char *path);

/* Cumulative over every source this parser has seen. */
const cl_parse_stats_t *cl_parser_stats(const cl_parser_t *p);

#ifdef __cplusplus
}
#endif

#endif
