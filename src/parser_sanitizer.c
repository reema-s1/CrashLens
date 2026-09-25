/* Sanitizer reports (AddressSanitizer, LeakSanitizer, ...):
 *
 *   ==4121==ERROR: AddressSanitizer: heap-use-after-free on address 0x6020...
 *   READ of size 4 at 0x602000000010 thread T0
 *       #0 0x55d0c4 in parse_header /src/codec.c:118:5
 *       #1 0x55d1f0 in decode_frame /src/codec.c:201
 *       #2 0x7f3a1c in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x29d90)
 *
 *   0x602000000010 is located 0 bytes inside of 4-byte region ...
 *   freed by thread T0 here:
 *       #0 ...
 *
 * Only the first stack, the one that faulted, is kept; the allocation and
 * deallocation stacks that follow describe other code paths. The stack ends
 * at the first line that is not a frame. */

#include <string.h>

#include "parser_internal.h"
#include "util.h"

#define MAX_PREAMBLE_LINES 64
#define MAX_FRAME_INDEX    (1ul << 20)

/* state >= 0: lines seen before the first frame.
 * state <  0: inside the stack; the last frame index is -(state + 2). */
#define IN_STACK(state)   ((state) < 0)
#define LAST_INDEX(state) ((unsigned long)(-((state) + 2)))
#define STACK_STATE(idx)  (-(int)(idx) - 2)

/* Skips "==PID==" and returns what follows, or NULL. */
static const char *skip_pid_prefix(const char *s, uint64_t *pid)
{
    uint64_t v;

    if (s[0] != '=' || s[1] != '=')
        return NULL;
    s += 2;
    if (cl_parse_u64(&s, 10, &v) != 0 || s[0] != '=' || s[1] != '=')
        return NULL;
    if (pid)
        *pid = v;
    return s + 2;
}

static int sanitizer_starts(const char *line)
{
    const char *s = skip_pid_prefix(cl_skip_space(line), NULL);

    return s && cl_starts_with(s, "ERROR: ") && strstr(s, "Sanitizer: ") != NULL;
}

static const char *copy_word(char *dst, size_t size, const char *s)
{
    const char *end = s;

    while (*end && !cl_isspace((unsigned char)*end))
        end++;
    cl_strlcpyn(dst, s, (size_t)(end - s), size);
    return cl_skip_space(end);
}

static int sanitizer_begin(cl_crash_event_t *ev, int *state, const char *line)
{
    uint64_t pid;
    const char *s = skip_pid_prefix(cl_skip_space(line), &pid);
    const char *tool, *desc;
    char word[CL_KIND_MAX];
    int signo;

    if (!s)
        return -1;
    tool = s + strlen("ERROR: ");
    desc = strstr(tool, "Sanitizer: ");
    if (!desc)
        return -1;
    desc += strlen("Sanitizer: ");
    if (pid <= INT64_MAX)
        ev->pid = (int64_t)pid;

    if (cl_starts_with(tool, "LeakSanitizer")) {
        cl_strlcpy(ev->kind, "memory-leak", sizeof(ev->kind));
    } else {
        desc = copy_word(word, sizeof(word), desc);
        /* "attempting double-free", "attempting free on address ..." */
        if (strcmp(word, "attempting") == 0 && *desc)
            copy_word(word, sizeof(word), desc);
        signo = cl_signal_from_name(word);
        if (signo) {
            ev->signal = signo;
            cl_strlcpy(ev->kind, cl_signal_name(signo), sizeof(ev->kind));
        } else {
            cl_strlcpy(ev->kind, word, sizeof(ev->kind));
        }
    }
    *state = 0;
    return 0;
}

/* "(module+0xoffset)" */
static int parse_module(const char *s, const char *end, cl_frame_t *f)
{
    const char *plus;
    const char *hex;
    uint64_t off;

    if (end - s < 2 || s[0] != '(' || end[-1] != ')')
        return -1;
    s++;
    end--;
    for (plus = end; plus > s && plus[-1] != '+'; plus--)
        ;
    if (plus == s || plus - 1 == s)
        return -1;
    hex = plus;
    if (cl_parse_hex_addr(&hex, &off) != 0 || hex != end)
        return -1;
    cl_strlcpyn(f->file, s, (size_t)(plus - 1 - s), sizeof(f->file));
    f->offset = off;
    f->flags |= CL_FRAME_MODULE_RELATIVE | CL_FRAME_HAS_OFFSET;
    return 0;
}

static int parse_frame(const char *s, unsigned long *index, cl_frame_t *f)
{
    const char *rest, *end, *tail, *build_id;
    uint64_t idx;
    int has_symbol = 0;

    memset(f, 0, sizeof(*f));
    s++;
    if (cl_parse_u64(&s, 10, &idx) != 0 || idx >= MAX_FRAME_INDEX ||
        !cl_isspace((unsigned char)*s))
        return -1;
    s = cl_skip_space(s);
    if (cl_parse_hex_addr(&s, &f->address) != 0 ||
        (*s != '\0' && !cl_isspace((unsigned char)*s)))
        return -1;
    f->flags |= CL_FRAME_HAS_ADDRESS;
    *index = (unsigned long)idx;

    rest = cl_skip_space(s);
    end = rest + strlen(rest);

    /* Newer runtimes append " (BuildId: <hex>)". */
    build_id = strstr(rest, " (BuildId: ");
    if (build_id && end[-1] == ')') {
        end = build_id;
        cl_trim_range(&rest, &end);
    }

    if (cl_starts_with(rest, "in ")) {
        rest = cl_skip_space(rest + 3);
        has_symbol = 1;
    }

    /* The location, if any, is the last space-separated token. */
    for (tail = end; tail > rest && tail[-1] != ' '; tail--)
        ;
    if (parse_module(tail, end, f) == 0 ||
        (has_symbol && tail > rest && cl_split_file_line(tail, end, f) == 0)) {
        end = tail;
        cl_trim_range(&rest, &end);
    } else if (!has_symbol) {
        /* "(<unknown module>)" and similar: nothing usable. */
        return 0;
    }

    if (has_symbol && end > rest && !(end - rest == 2 && rest[0] == '?' && rest[1] == '?'))
        cl_strlcpyn(f->symbol, rest, (size_t)(end - rest), sizeof(f->symbol));
    return 0;
}

/* "... thread T3" or "... thread T3 (worker)" */
static void parse_thread(cl_crash_event_t *ev, const char *s)
{
    const char *t = strstr(s, " thread T");
    const char *end;

    if (!t || ev->thread[0] != '\0')
        return;
    t += strlen(" thread ");
    end = t + 1;
    while (cl_isdigit((unsigned char)*end))
        end++;
    if (end > t + 1)
        cl_strlcpyn(ev->thread, t, (size_t)(end - t), sizeof(ev->thread));
}

static cl_step_t sanitizer_step(cl_crash_event_t *ev, int *state, const char *line)
{
    const char *s = cl_skip_space(line);
    unsigned long index;
    cl_frame_t frame, *slot;

    if (!IN_STACK(*state)) {
        if (*s == '#') {
            if (parse_frame(s, &index, &frame) == 0 && index == 0) {
                *state = STACK_STATE(0ul);
                slot = cl_event_push_frame(ev);
                if (slot)
                    *slot = frame;
            }
            return CL_STEP_CONTINUE;
        }
        if (cl_starts_with(s, "SUMMARY:") || strstr(s, "==ABORTING"))
            return CL_STEP_INVALID;
        parse_thread(ev, s);
        if (++*state > MAX_PREAMBLE_LINES)
            return CL_STEP_INVALID;
        return CL_STEP_CONTINUE;
    }

    if (*s != '#')
        return CL_STEP_DONE_REPLAY;
    if (parse_frame(s, &index, &frame) != 0)
        return CL_STEP_CONTINUE;
    if (index <= LAST_INDEX(*state))
        return CL_STEP_DONE; /* a second stack began without a gap */
    *state = STACK_STATE(index);
    slot = cl_event_push_frame(ev);
    if (slot)
        *slot = frame;
    return CL_STEP_CONTINUE;
}

static void sanitizer_eof(cl_crash_event_t *ev, int state)
{
    /* A stack that simply runs to the end of input is complete. */
    if (!IN_STACK(state))
        ev->flags |= CL_EVENT_TRUNCATED;
}

const cl_adapter_t cl_sanitizer_adapter = {
    CL_FORMAT_SANITIZER,
    sanitizer_starts,
    sanitizer_begin,
    sanitizer_step,
    sanitizer_eof,
};
