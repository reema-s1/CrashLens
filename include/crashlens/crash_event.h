#ifndef CRASHLENS_CRASH_EVENT_H
#define CRASHLENS_CRASH_EVENT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CL_MAX_STACK_DEPTH 64
#define CL_SYMBOL_MAX      128
#define CL_FILE_MAX        192
#define CL_NAME_MAX        64
#define CL_KIND_MAX        48
#define CL_SOURCE_MAX      260

/* Input formats understood by the parser. */
typedef enum {
    CL_FORMAT_AUTO = 0,   /* detect per event */
    CL_FORMAT_NATIVE,     /* "=== CRASH ===" block format */
    CL_FORMAT_SANITIZER   /* AddressSanitizer-style "==PID==ERROR:" reports */
} cl_log_format_t;

/* cl_frame_t.flags */
enum {
    CL_FRAME_HAS_ADDRESS     = 1u << 0,
    CL_FRAME_HAS_OFFSET      = 1u << 1,
    CL_FRAME_MODULE_RELATIVE = 1u << 2, /* `file` is a module and `offset` is
                                           relative to its load address */
    CL_FRAME_SYMBOLICATED    = 1u << 3  /* symbol filled in from a symbol map */
};

typedef struct {
    uint64_t address;
    uint64_t offset;               /* within the function (or module) */
    char     symbol[CL_SYMBOL_MAX]; /* function name; empty when unresolved */
    char     file[CL_FILE_MAX];    /* source file or module path; may be empty */
    int      line;                 /* 0 when unknown */
    unsigned flags;
} cl_frame_t;

/* cl_crash_event_t.flags */
enum {
    CL_EVENT_TRUNCATED       = 1u << 0, /* report ended before its terminator */
    CL_EVENT_STACK_TRUNCATED = 1u << 1, /* deeper than CL_MAX_STACK_DEPTH */
    CL_EVENT_TIME_ESTIMATED  = 1u << 2  /* timestamp taken from the file mtime */
};

typedef struct {
    int64_t         timestamp;   /* seconds since the Unix epoch (UTC); 0 = unknown */
    int64_t         pid;         /* -1 = unknown */
    int             signal;      /* signal number; 0 = none or unknown */
    char            kind[CL_KIND_MAX];     /* "SIGSEGV", "heap-use-after-free", ... */
    char            process[CL_NAME_MAX];
    char            thread[CL_NAME_MAX];
    char            source[CL_SOURCE_MAX]; /* input the event was read from */
    unsigned long   source_line;           /* 1-based line the event starts on */
    cl_log_format_t format;
    unsigned        flags;
    size_t          frame_count;
    cl_frame_t      frames[CL_MAX_STACK_DEPTH];
} cl_crash_event_t;

/* Clears the header fields and the stack. Frame storage is not zeroed;
 * cl_event_push_frame() initialises each frame as it is added. */
void cl_event_reset(cl_crash_event_t *ev);

/* Appends an empty frame (see cl_frame_init). Returns NULL (and flags the
 * event as stack-truncated) when the stack is already full. */
cl_frame_t *cl_event_push_frame(cl_crash_event_t *ev);

/* Empties a frame: no address, symbol, location or flags. Only the string
 * terminators are written, not the whole buffers. */
void cl_frame_init(cl_frame_t *f);

const char *cl_format_name(cl_log_format_t fmt);
int         cl_format_from_name(const char *name, cl_log_format_t *out);

/* Signal numbers follow the Linux numbering. */
int         cl_signal_from_name(const char *name); /* 0 if unknown */
const char *cl_signal_name(int signo);             /* NULL if unknown */

#ifdef __cplusplus
}
#endif

#endif
