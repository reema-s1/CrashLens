#ifndef CRASHLENS_PARSER_INTERNAL_H
#define CRASHLENS_PARSER_INTERNAL_H

#include <stddef.h>

#include "crashlens/crash_event.h"

/* A format adapter turns lines into crash events. The generic parser owns
 * line splitting, decoding and bookkeeping; an adapter only recognises the
 * first line of a report and then consumes lines until the report ends.
 *
 * Every line passed to an adapter is NUL-terminated, contains no '\0' or
 * '\n', has trailing whitespace removed and is at most CL_MAX_LINE bytes. */

typedef enum {
    CL_STEP_CONTINUE,      /* line consumed, report still open */
    CL_STEP_DONE,          /* report complete, line consumed */
    CL_STEP_DONE_REPLAY,   /* report complete, line belongs to what follows */
    CL_STEP_INVALID,       /* report unusable, line consumed */
    CL_STEP_INVALID_REPLAY /* report unusable, line belongs to what follows */
} cl_step_t;

typedef struct {
    cl_log_format_t format;
    /* Cheap test: could this line start a report? */
    int (*starts)(const char *line);
    /* Initialise a freshly reset event from the opening line. Returns 0 on
     * success, -1 if the line turned out not to be a valid opener. */
    int (*begin)(cl_crash_event_t *ev, int *state, const char *line);
    cl_step_t (*step)(cl_crash_event_t *ev, int *state, const char *line);
    /* Input ended while the report was open; mark it truncated if needed. */
    void (*eof)(cl_crash_event_t *ev, int state);
} cl_adapter_t;

extern const cl_adapter_t cl_native_adapter;
extern const cl_adapter_t cl_sanitizer_adapter;

/* Shared by adapters: parses "file:line" at the end of [s, end). On success
 * stores the file and line and returns 0. */
int cl_split_file_line(const char *s, const char *end, cl_frame_t *f);

#endif
