/* The native CrashLens report format:
 *
 *   === CRASH ===
 *   Time: 2026-09-25T14:03:11Z
 *   Process: indexer [4121]
 *   Thread: worker-3
 *   Signal: SIGSEGV (11)
 *   Backtrace:
 *     #0  0x00007f3a1c2b1c20 parse_header + 32 (codec.c:118)
 *     #1  0x00007f3a1c2b0010 decode_frame + 0x90
 *     #2  0x0000560d4e2a1f00 ??
 *   === END ===
 *
 * Reports may be embedded in ordinary log output; lines outside a report
 * are ignored. Header keys are optional and unknown keys are skipped. A
 * frame is "#<index> 0x<address> <symbol>[ + <offset>][ (<file>:<line>)]",
 * where the symbol may be "??" when unresolved.
 */

#include <string.h>

#include "parser_internal.h"
#include "util.h"

#define NATIVE_BEGIN "=== CRASH ==="
#define NATIVE_END   "=== END ==="

/* The adapter state packs the phase into the low two bits and the next
 * acceptable frame index above them. */
enum { PHASE_HEADER, PHASE_FRAMES, PHASE_TRAILER };
#define PHASE(state)       ((state) & 3)
#define NEXT_INDEX(state)  ((unsigned long)(state) >> 2)
#define MAKE_STATE(ph, ix) ((int)(((ix) << 2) | (ph)))
#define MAX_FRAME_INDEX    (1ul << 20)

static int native_starts(const char *line)
{
    return strcmp(cl_skip_space(line), NATIVE_BEGIN) == 0;
}

static int native_begin(cl_crash_event_t *ev, int *state, const char *line)
{
    (void)ev;
    (void)line;
    *state = MAKE_STATE(PHASE_HEADER, 0ul);
    return 0;
}

/* "name [pid]" or just "name". */
static void parse_process(cl_crash_event_t *ev, const char *value)
{
    const char *end = value + strlen(value);
    const char *open = strrchr(value, '[');

    if (open && end > value && end[-1] == ']') {
        const char *digits = open + 1;
        uint64_t pid;

        if (cl_parse_u64(&digits, 10, &pid) == 0 && digits == end - 1 &&
            pid <= INT64_MAX) {
            ev->pid = (int64_t)pid;
            end = open;
            cl_trim_range(&value, &end);
        }
    }
    cl_strlcpyn(ev->process, value, (size_t)(end - value), sizeof(ev->process));
}

/* "SIGSEGV (11)", "SIGSEGV" or "11". The signal name only becomes the
 * event kind if an Exception header has not already provided one. */
static void parse_signal(cl_crash_event_t *ev, const char *value)
{
    const char *s = value;
    char name[CL_KIND_MAX] = "";
    uint64_t num;

    if (cl_isdigit((unsigned char)*s)) {
        if (cl_parse_u64(&s, 10, &num) != 0 || num > 255)
            return;
        ev->signal = (int)num;
        if (cl_signal_name(ev->signal))
            cl_strlcpy(name, cl_signal_name(ev->signal), sizeof(name));
    } else {
        const char *name_end = s;

        while (*name_end && !cl_isspace((unsigned char)*name_end) && *name_end != '(')
            name_end++;
        cl_strlcpyn(name, s, (size_t)(name_end - s), sizeof(name));
        ev->signal = cl_signal_from_name(name);

        s = cl_skip_space(name_end);
        if (*s == '(') {
            s++;
            if (cl_parse_u64(&s, 10, &num) == 0 && *s == ')' && num <= 255)
                ev->signal = (int)num;
        }
    }

    if (ev->kind[0] == '\0')
        cl_strlcpy(ev->kind, name, sizeof(ev->kind));
}

static void parse_header(cl_crash_event_t *ev, const char *line)
{
    const char *colon = strchr(line, ':');
    const char *value;
    size_t keylen;
    uint64_t num;
    int64_t t;

    if (!colon)
        return;
    keylen = (size_t)(colon - line);
    value = cl_skip_space(colon + 1);

#define KEY_IS(k) (keylen == sizeof(k) - 1 && memcmp(line, k, keylen) == 0)
    if (KEY_IS("Time")) {
        if (cl_parse_iso8601(value, &t) == 0)
            ev->timestamp = t;
    } else if (KEY_IS("Process")) {
        parse_process(ev, value);
    } else if (KEY_IS("PID")) {
        if (cl_parse_u64(&value, 10, &num) == 0 && *value == '\0' && num <= INT64_MAX)
            ev->pid = (int64_t)num;
    } else if (KEY_IS("Thread")) {
        cl_strlcpy(ev->thread, value, sizeof(ev->thread));
    } else if (KEY_IS("Signal")) {
        parse_signal(ev, value);
    } else if (KEY_IS("Exception")) {
        /* More specific than the signal it usually ends in (SIGABRT). */
        cl_strlcpy(ev->kind, value, sizeof(ev->kind));
    }
#undef KEY_IS
}

/* Parses a frame line starting at '#'. */
static int parse_frame(const char *s, unsigned long *index, cl_frame_t *f)
{
    const char *rest, *end, *q;
    uint64_t idx;

    memset(f, 0, sizeof(*f));
    s++;
    if (cl_parse_u64(&s, 10, &idx) != 0 || idx >= MAX_FRAME_INDEX ||
        !cl_isspace((unsigned char)*s))
        return -1;
    s = cl_skip_space(s);
    if (cl_parse_hex_addr(&s, &f->address) != 0)
        return -1;
    if (*s != '\0' && !cl_isspace((unsigned char)*s))
        return -1;
    f->flags |= CL_FRAME_HAS_ADDRESS;
    *index = (unsigned long)idx;

    rest = cl_skip_space(s);
    end = rest + strlen(rest);

    /* Trailing "(file:line)". Search from the right so that C++ parameter
     * lists in the symbol are left alone. */
    if (end > rest && end[-1] == ')') {
        const char *open = end - 1;

        while (open > rest && *open != '(')
            open--;
        if (*open == '(' && cl_split_file_line(open + 1, end - 1, f) == 0) {
            end = open;
            cl_trim_range(&rest, &end);
        }
    }

    /* " + offset" */
    for (q = end - 1; q > rest + 1; q--) {
        if (q[0] == '+' && q[-1] == ' ' && q + 1 < end && q[1] == ' ') {
            const char *num = cl_skip_space(q + 1);
            int base = num[0] == '0' && (num[1] == 'x' || num[1] == 'X') ? 16 : 10;
            uint64_t off;

            if (cl_parse_u64(&num, base, &off) == 0 && num == end) {
                f->offset = off;
                f->flags |= CL_FRAME_HAS_OFFSET;
                end = q;
                cl_trim_range(&rest, &end);
            }
            break;
        }
    }

    if (!(end - rest == 2 && rest[0] == '?' && rest[1] == '?'))
        cl_strlcpyn(f->symbol, rest, (size_t)(end - rest), sizeof(f->symbol));
    return 0;
}

static cl_step_t native_step(cl_crash_event_t *ev, int *state, const char *line)
{
    const char *s = cl_skip_space(line);
    unsigned long index;
    cl_frame_t frame, *slot;

    if (strcmp(s, NATIVE_END) == 0)
        return CL_STEP_DONE;
    if (*s == '\0')
        return CL_STEP_CONTINUE;

    switch (PHASE(*state)) {
    case PHASE_HEADER:
        if (strcmp(s, "Backtrace:") == 0)
            *state = MAKE_STATE(PHASE_FRAMES, 0ul);
        else
            parse_header(ev, s);
        break;

    case PHASE_FRAMES:
        if (*s != '#') {
            /* The backtrace is one contiguous block. */
            if (ev->frame_count > 0)
                *state = MAKE_STATE(PHASE_TRAILER, 0ul);
            break;
        }
        /* Malformed or out-of-order frame lines are skipped. */
        if (parse_frame(s, &index, &frame) != 0 || index < NEXT_INDEX(*state))
            break;
        *state = MAKE_STATE(PHASE_FRAMES, index + 1);
        slot = cl_event_push_frame(ev);
        if (slot)
            *slot = frame;
        break;

    default:
        break;
    }
    return CL_STEP_CONTINUE;
}

static void native_eof(cl_crash_event_t *ev, int state)
{
    (void)state;
    /* Only the end marker completes a native report. */
    ev->flags |= CL_EVENT_TRUNCATED;
}

const cl_adapter_t cl_native_adapter = {
    CL_FORMAT_NATIVE,
    native_starts,
    native_begin,
    native_step,
    native_eof,
};
