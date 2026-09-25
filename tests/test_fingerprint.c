#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "crashlens/fingerprint.h"
#include "test.h"

/* Builds an event from a NULL-terminated list of symbols; each frame gets
 * an address, offset and line derived from `salt` so that two events
 * built with different salts differ in everything except the call path. */
static cl_crash_event_t *make_event(unsigned salt, ...)
{
    cl_crash_event_t *ev = malloc(sizeof(*ev));
    const char *sym;
    va_list ap;

    cl_event_reset(ev);
    ev->pid = 1000 + salt;
    ev->timestamp = 1700000000 + salt * 3600;
    va_start(ap, salt);
    while ((sym = va_arg(ap, const char *)) != NULL) {
        cl_frame_t *f = cl_event_push_frame(ev);

        f->address = 0x7f0000000000ull + salt * 0x1000 + ev->frame_count * 0x40;
        f->offset = salt * 7 + ev->frame_count;
        f->line = (int)(salt + ev->frame_count);
        f->flags = CL_FRAME_HAS_ADDRESS | CL_FRAME_HAS_OFFSET;
        strcpy(f->file, "src.c");
        if (strcmp(sym, "??") != 0)
            strcpy(f->symbol, sym);
    }
    va_end(ap);
    return ev;
}

static void test_fnv_vectors(void)
{
    CHECK_U64(cl_fnv1a64("", 0, CL_FNV1A64_INIT), 0xcbf29ce484222325ull);
    CHECK_U64(cl_fnv1a64("a", 1, CL_FNV1A64_INIT), 0xaf63dc4c8601ec8cull);
    CHECK_U64(cl_fnv1a64("foobar", 6, CL_FNV1A64_INIT), 0x85944171f73967e8ull);
}

static void test_stable_across_runs(void)
{
    cl_fp_options_t o;
    cl_crash_event_t *a = make_event(1, "parse", "decode", "load", "main", NULL);
    cl_crash_event_t *b = make_event(9, "parse", "decode", "load", "main", NULL);

    cl_fp_options_default(&o);
    CHECK(a->frames[0].address != b->frames[0].address);
    CHECK_U64(cl_fingerprint(a, &o), cl_fingerprint(b, &o));
    /* The hash is exactly FNV-1a over the signature. */
    CHECK_U64(cl_fingerprint(a, &o),
              cl_fnv1a64("parse|decode|load|main", 22, CL_FNV1A64_INIT));
    free(a);
    free(b);
}

static void test_discriminates(void)
{
    cl_fp_options_t o;
    cl_crash_event_t *base = make_event(1, "a", "b", "c", "d", "e", "f", NULL);
    cl_crash_event_t *swapped = make_event(1, "a", "c", "b", "d", "e", "f", NULL);
    cl_crash_event_t *top5 = make_event(1, "a", "b", "c", "d", "X", "f", NULL);
    cl_crash_event_t *deep = make_event(1, "a", "b", "c", "d", "e", "Y", NULL);
    cl_crash_event_t *shorter = make_event(1, "a", "b", "c", "d", NULL);

    cl_fp_options_default(&o);
    CHECK(cl_fingerprint(base, &o) != cl_fingerprint(swapped, &o));
    CHECK(cl_fingerprint(base, &o) != cl_fingerprint(top5, &o));
    CHECK(cl_fingerprint(base, &o) != cl_fingerprint(shorter, &o));
    /* Frame 6 is below the default depth ... */
    CHECK_U64(cl_fingerprint(base, &o), cl_fingerprint(deep, &o));
    /* ... but counts when the whole stack is used. */
    o.top_n = 0;
    CHECK(cl_fingerprint(base, &o) != cl_fingerprint(deep, &o));
    free(base);
    free(swapped);
    free(top5);
    free(deep);
    free(shorter);
}

static void test_separator_prevents_concat_collisions(void)
{
    cl_fp_options_t o;
    cl_crash_event_t *a = make_event(1, "ab", "c", NULL);
    cl_crash_event_t *b = make_event(1, "a", "bc", NULL);

    cl_fp_options_default(&o);
    CHECK(cl_fingerprint(a, &o) != cl_fingerprint(b, &o));
    free(a);
    free(b);
}

static void test_noise_frames_skipped(void)
{
    cl_fp_options_t o;
    char sig[256];
    cl_crash_event_t *plain = make_event(1, "check_len", "parse", "main", NULL);
    cl_crash_event_t *aborted = make_event(2, "__pthread_kill_implementation",
                                           "raise", "abort", "__assert_fail",
                                           "check_len", "parse", "main", NULL);
    cl_crash_event_t *asan = make_event(3, "__asan_report_load4",
                                        "__asan::ReportGenericError", "check_len",
                                        "parse", "main", NULL);
    cl_crash_event_t *only_noise = make_event(4, "raise", "abort", NULL);

    cl_fp_options_default(&o);
    CHECK_U64(cl_fingerprint(aborted, &o), cl_fingerprint(plain, &o));
    CHECK_U64(cl_fingerprint(asan, &o), cl_fingerprint(plain, &o));
    CHECK_INT(cl_fingerprint_first_frame(aborted, &o), 4);

    cl_fingerprint_signature(only_noise, &o, sig, sizeof(sig));
    CHECK_STR(sig, "raise|abort");

    o.skip_noise = 0;
    CHECK(cl_fingerprint(aborted, &o) != cl_fingerprint(plain, &o));
    free(plain);
    free(aborted);
    free(asan);
    free(only_noise);
}

static void test_tokens(void)
{
    cl_frame_t f;
    char tok[64];

    memset(&f, 0, sizeof(f));
    strcpy(f.symbol, "inflate_block.isra.0");
    cl_frame_token(&f, tok, sizeof(tok));
    CHECK_STR(tok, "inflate_block");

    strcpy(f.symbol, "flush.constprop.3.cold");
    cl_frame_token(&f, tok, sizeof(tok));
    CHECK_STR(tok, "flush");

    strcpy(f.symbol, "Reader::next() [clone .cold]");
    cl_frame_token(&f, tok, sizeof(tok));
    CHECK_STR(tok, "Reader::next()");

    f.symbol[0] = '\0';
    CHECK_INT(cl_frame_token(&f, tok, sizeof(tok)), 2);
    CHECK_STR(tok, "??");

    strcpy(f.file, "/lib/x86_64-linux-gnu/libc.so.6");
    f.offset = 0x29d90;
    f.flags = CL_FRAME_MODULE_RELATIVE | CL_FRAME_HAS_OFFSET;
    cl_frame_token(&f, tok, sizeof(tok));
    CHECK_STR(tok, "libc.so.6+0x29d90");
}

static void test_signature(void)
{
    cl_fp_options_t o;
    cl_crash_event_t *ev = make_event(1, "alpha", "??", "gamma", "delta", "eps",
                                      "zeta", NULL);
    cl_crash_event_t *empty = make_event(1, NULL);
    char sig[64], tiny[8];

    cl_fp_options_default(&o);
    CHECK_INT(cl_fingerprint_signature(ev, &o, sig, sizeof(sig)), 24);
    CHECK_STR(sig, "alpha|??|gamma|delta|eps");

    CHECK_INT(cl_fingerprint_signature(ev, &o, tiny, sizeof(tiny)), 24);
    CHECK_STR(tiny, "alpha|?");

    o.top_n = 2;
    cl_fingerprint_signature(ev, &o, sig, sizeof(sig));
    CHECK_STR(sig, "alpha|??");

    CHECK_INT(cl_fingerprint_signature(empty, &o, sig, sizeof(sig)), 0);
    CHECK_STR(sig, "");
    CHECK_U64(cl_fingerprint(empty, &o), CL_FNV1A64_INIT);
    free(ev);
    free(empty);
}

const test_case_t fingerprint_tests[] = {
    { "fnv_vectors", test_fnv_vectors },
    { "stable_across_runs", test_stable_across_runs },
    { "discriminates", test_discriminates },
    { "separator_prevents_concat_collisions", test_separator_prevents_concat_collisions },
    { "noise_frames_skipped", test_noise_frames_skipped },
    { "tokens", test_tokens },
    { "signature", test_signature },
    { NULL, NULL },
};
