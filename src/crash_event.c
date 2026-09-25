#include "crashlens/crash_event.h"

#include <string.h>

#include "util.h"

void cl_event_reset(cl_crash_event_t *ev)
{
    ev->timestamp = 0;
    ev->pid = -1;
    ev->signal = 0;
    ev->kind[0] = '\0';
    ev->process[0] = '\0';
    ev->thread[0] = '\0';
    ev->source[0] = '\0';
    ev->source_line = 0;
    ev->format = CL_FORMAT_AUTO;
    ev->flags = 0;
    ev->frame_count = 0;
}

void cl_frame_init(cl_frame_t *f)
{
    f->address = 0;
    f->offset = 0;
    f->symbol[0] = '\0';
    f->file[0] = '\0';
    f->line = 0;
    f->flags = 0;
}

cl_frame_t *cl_event_push_frame(cl_crash_event_t *ev)
{
    cl_frame_t *f;

    if (ev->frame_count >= CL_MAX_STACK_DEPTH) {
        ev->flags |= CL_EVENT_STACK_TRUNCATED;
        return NULL;
    }
    f = &ev->frames[ev->frame_count++];
    cl_frame_init(f);
    return f;
}

static const struct {
    cl_log_format_t fmt;
    const char *name;
} format_names[] = {
    { CL_FORMAT_AUTO,      "auto" },
    { CL_FORMAT_NATIVE,    "native" },
    { CL_FORMAT_SANITIZER, "sanitizer" },
};

const char *cl_format_name(cl_log_format_t fmt)
{
    size_t i;

    for (i = 0; i < CL_ARRAY_LEN(format_names); i++)
        if (format_names[i].fmt == fmt)
            return format_names[i].name;
    return "unknown";
}

int cl_format_from_name(const char *name, cl_log_format_t *out)
{
    size_t i;

    for (i = 0; i < CL_ARRAY_LEN(format_names); i++) {
        if (strcmp(format_names[i].name, name) == 0) {
            *out = format_names[i].fmt;
            return 0;
        }
    }
    return -1;
}

static const struct {
    int signo;
    const char *name;
} signal_names[] = {
    {  1, "SIGHUP" },  {  2, "SIGINT" },  {  3, "SIGQUIT" }, {  4, "SIGILL" },
    {  5, "SIGTRAP" }, {  6, "SIGABRT" }, {  7, "SIGBUS" },  {  8, "SIGFPE" },
    {  9, "SIGKILL" }, { 10, "SIGUSR1" }, { 11, "SIGSEGV" }, { 12, "SIGUSR2" },
    { 13, "SIGPIPE" }, { 14, "SIGALRM" }, { 15, "SIGTERM" }, { 16, "SIGSTKFLT" },
    { 24, "SIGXCPU" }, { 25, "SIGXFSZ" }, { 31, "SIGSYS" },
};

int cl_signal_from_name(const char *name)
{
    size_t i;

    for (i = 0; i < CL_ARRAY_LEN(signal_names); i++)
        if (strcmp(signal_names[i].name, name) == 0)
            return signal_names[i].signo;
    /* Accept the short form ("SEGV") used by sanitizers. */
    for (i = 0; i < CL_ARRAY_LEN(signal_names); i++)
        if (strcmp(signal_names[i].name + 3, name) == 0)
            return signal_names[i].signo;
    return 0;
}

const char *cl_signal_name(int signo)
{
    size_t i;

    for (i = 0; i < CL_ARRAY_LEN(signal_names); i++)
        if (signal_names[i].signo == signo)
            return signal_names[i].name;
    return NULL;
}
