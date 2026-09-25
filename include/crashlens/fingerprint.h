#ifndef CRASHLENS_FINGERPRINT_H
#define CRASHLENS_FINGERPRINT_H

#include <stddef.h>
#include <stdint.h>

#include "crashlens/crash_event.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CL_FP_DEFAULT_TOP_N 5

typedef struct {
    /* Number of frames that contribute to the fingerprint; <= 0 uses the
     * whole stack. */
    int top_n;
    /* Skip crash-handling frames (raise, abort, __assert_fail, sanitizer
     * runtime, ...) at the top of the stack before counting top_n. They
     * describe how the process died, not where the bug is. */
    int skip_noise;
} cl_fp_options_t;

void cl_fp_options_default(cl_fp_options_t *opts);

/* A crash fingerprint: FNV-1a (64-bit) over the canonical signature,
 * i.e. the '|'-joined, normalised function names of the top frames.
 * Addresses, offsets, line numbers, PIDs and timestamps do not contribute,
 * so the same bug hashes identically across runs, ASLR slides and
 * rebuilds that do not change the call path. */
uint64_t cl_fingerprint(const cl_crash_event_t *ev, const cl_fp_options_t *opts);

/* Writes the canonical signature, e.g. "parse_header|decode_frame|main",
 * snprintf-style: returns the full length, output is always terminated. */
size_t cl_fingerprint_signature(const cl_crash_event_t *ev,
                                const cl_fp_options_t *opts,
                                char *buf, size_t size);

/* The normalised token one frame contributes: its function name with
 * compiler clone suffixes removed, "module+0xoffset" for an unsymbolised
 * frame with a module-relative offset, or "??". Returns the length. */
size_t cl_frame_token(const cl_frame_t *f, char *buf, size_t size);

/* Index of the first frame that contributes to the fingerprint. */
size_t cl_fingerprint_first_frame(const cl_crash_event_t *ev,
                                  const cl_fp_options_t *opts);

uint64_t cl_fnv1a64(const void *data, size_t len, uint64_t hash);
#define CL_FNV1A64_INIT 0xcbf29ce484222325ull

#ifdef __cplusplus
}
#endif

#endif
