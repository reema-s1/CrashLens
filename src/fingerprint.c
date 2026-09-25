#include "crashlens/fingerprint.h"

#include <stdio.h>
#include <string.h>

#include "util.h"

#define FNV1A64_PRIME 0x100000001b3ull

/* Frames that belong to the crash machinery rather than the bug. */
static const char *const noise_exact[] = {
    "raise", "abort", "gsignal", "__GI_raise", "__GI_abort",
    "pthread_kill", "__pthread_kill", "__pthread_kill_implementation",
    "__pthread_kill_internal",
    "__assert_fail", "__assert_fail_base", "__assert_perror_fail",
    "_assert", "_wassert",
    "__stack_chk_fail", "__fortify_fail", "__chk_fail",
    "__libc_message", "__libc_fatal",
    "_sigtramp", "__restore_rt", "__kernel_rt_sigreturn",
    "__cxa_throw", "__cxa_rethrow", "std::terminate()",
    "__gnu_cxx::__verbose_terminate_handler()",
    "__cxxabiv1::__terminate(void (*)())",
    "RaiseException", "RtlRaiseException", "KiUserExceptionDispatcher",
    "_CxxThrowException", "_invoke_watson", "_invalid_parameter",
};

static const char *const noise_prefix[] = {
    "__asan_", "__asan::", "__lsan::", "__msan::", "__tsan::",
    "__ubsan_", "__ubsan::", "__sanitizer_", "__sanitizer::",
    "__interceptor_", "___interceptor_",
};

/* Suffixes compilers append to cloned or split functions. They vary with
 * optimisation decisions, not with the call path. */
static const char *const clone_suffixes[] = {
    ".isra.", ".constprop.", ".part.", ".cold", ".lto_priv.", ".llvm.",
    " [clone ",
};

void cl_fp_options_default(cl_fp_options_t *opts)
{
    opts->top_n = CL_FP_DEFAULT_TOP_N;
    opts->skip_noise = 1;
}

uint64_t cl_fnv1a64(const void *data, size_t len, uint64_t hash)
{
    const unsigned char *p = data;
    size_t i;

    for (i = 0; i < len; i++) {
        hash ^= p[i];
        hash *= FNV1A64_PRIME;
    }
    return hash;
}

size_t cl_frame_token(const cl_frame_t *f, char *buf, size_t size)
{
    size_t len, i;

    if (f->symbol[0] != '\0') {
        const char *sym = cl_skip_space(f->symbol);

        len = strlen(sym);
        for (i = 0; i < CL_ARRAY_LEN(clone_suffixes); i++) {
            const char *hit = strstr(sym, clone_suffixes[i]);

            if (hit && hit != sym && (size_t)(hit - sym) < len)
                len = (size_t)(hit - sym);
        }
        cl_strlcpyn(buf, sym, len, size);
        return len < size ? len : size - 1;
    }

    if ((f->flags & CL_FRAME_MODULE_RELATIVE) && f->file[0] != '\0') {
        int n = snprintf(buf, size, "%s+0x%llx", cl_basename(f->file),
                         (unsigned long long)f->offset);

        return n < 0 ? 0 : (size_t)n < size ? (size_t)n : size - 1;
    }

    cl_strlcpy(buf, "??", size);
    return 2;
}

static int is_noise(const char *token)
{
    size_t i;

    for (i = 0; i < CL_ARRAY_LEN(noise_exact); i++)
        if (strcmp(token, noise_exact[i]) == 0)
            return 1;
    for (i = 0; i < CL_ARRAY_LEN(noise_prefix); i++)
        if (cl_starts_with(token, noise_prefix[i]))
            return 1;
    return 0;
}

size_t cl_fingerprint_first_frame(const cl_crash_event_t *ev,
                                  const cl_fp_options_t *opts)
{
    char token[CL_SYMBOL_MAX];
    size_t i;

    if (!opts->skip_noise)
        return 0;
    for (i = 0; i < ev->frame_count; i++) {
        cl_frame_token(&ev->frames[i], token, sizeof(token));
        if (!is_noise(token))
            return i;
    }
    /* Nothing but crash machinery: better to use it than an empty stack. */
    return 0;
}

static size_t frame_end(const cl_crash_event_t *ev, const cl_fp_options_t *opts,
                        size_t first)
{
    if (opts->top_n <= 0 || ev->frame_count - first <= (size_t)opts->top_n)
        return ev->frame_count;
    return first + (size_t)opts->top_n;
}

uint64_t cl_fingerprint(const cl_crash_event_t *ev, const cl_fp_options_t *opts)
{
    char token[CL_SYMBOL_MAX + CL_FILE_MAX];
    size_t first = cl_fingerprint_first_frame(ev, opts);
    size_t end = frame_end(ev, opts, first);
    uint64_t hash = CL_FNV1A64_INIT;
    size_t i, len;

    for (i = first; i < end; i++) {
        if (i > first)
            hash = cl_fnv1a64("|", 1, hash);
        len = cl_frame_token(&ev->frames[i], token, sizeof(token));
        hash = cl_fnv1a64(token, len, hash);
    }
    return hash;
}

size_t cl_fingerprint_signature(const cl_crash_event_t *ev,
                                const cl_fp_options_t *opts,
                                char *buf, size_t size)
{
    char token[CL_SYMBOL_MAX + CL_FILE_MAX];
    size_t first = cl_fingerprint_first_frame(ev, opts);
    size_t end = frame_end(ev, opts, first);
    size_t total = 0;
    size_t i, len;

    if (size > 0)
        buf[0] = '\0';
    for (i = first; i < end; i++) {
        len = cl_frame_token(&ev->frames[i], token, sizeof(token));
        if (i > first) {
            if (total + 1 < size)
                buf[total] = '|';
            total++;
        }
        if (total < size)
            cl_strlcpyn(buf + total, token, len, size - total);
        total += len;
    }
    if (size > 0)
        buf[total < size ? total : size - 1] = '\0';
    return total;
}
