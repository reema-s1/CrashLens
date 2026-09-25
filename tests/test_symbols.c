#include <stdlib.h>
#include <string.h>

#include "crashlens/fingerprint.h"
#include "crashlens/parser.h"
#include "crashlens/symbols.h"
#include "test.h"

#define LOAD_BIAS 0x555555400000ull

static cl_symtab_t *load_fixture(void)
{
    cl_symtab_t *t = cl_symtab_create();
    char path[512];

    snprintf(path, sizeof(path), "%s/indexer.sym", TEST_DATA_DIR);
    CHECK_INT(cl_symtab_load_file(t, path), 0);
    return t;
}

static const char *name_at(const cl_symtab_t *t, uint64_t addr)
{
    const cl_symbol_t *s = cl_symtab_lookup(t, addr);

    return s ? s->name : "(none)";
}

static void test_load_and_lookup(void)
{
    cl_symtab_t *t = load_fixture();
    const cl_symbol_t *s;

    CHECK_INT(cl_symtab_count(t), 9);
    CHECK_INT(cl_symtab_bad_lines(t), 1);

    CHECK_STR(name_at(t, 0x400fff), "(none)");
    CHECK_STR(name_at(t, 0x401000), "_start");
    CHECK_STR(name_at(t, 0x40103f), "_start");
    CHECK_STR(name_at(t, 0x401040), "segment_load");
    /* Unsized symbols run up to the next address... */
    CHECK_STR(name_at(t, 0x4012ff), "decode_frame.isra.0");
    /* ...and code wins over an absolute symbol at the same address. */
    CHECK_STR(name_at(t, 0x401300), "parse_header");
    CHECK_STR(name_at(t, 0x401410), "worker_main(Worker&, int)");
    CHECK_STR(name_at(t, 0x40148b), "tiny_helper");
    /* Past a sized symbol's end, and inside data, nothing resolves. */
    CHECK_STR(name_at(t, 0x40148c), "(none)");
    CHECK_STR(name_at(t, 0x404010), "(none)");
    CHECK_STR(name_at(t, 0x7fffffff), "(none)");

    s = cl_symtab_lookup(t, 0x401301);
    CHECK(s != NULL);
    if (s) {
        CHECK_STR(s->file, "/src/indexer/codec.c");
        CHECK_INT(s->line, 101);
        CHECK_U64(s->end, 0x401400);
    }
    cl_symtab_destroy(t);
}

static void test_merge_recomputes_extents(void)
{
    static const char first[] = "1000 T a\n3000 T c\n";
    static const char second[] = "2000 T b\n";
    cl_symtab_t *t = cl_symtab_create();

    cl_symtab_load_buffer(t, first, sizeof(first) - 1);
    CHECK_STR(name_at(t, 0x2500), "a");
    cl_symtab_load_buffer(t, second, sizeof(second) - 1);
    CHECK_STR(name_at(t, 0x1fff), "a");
    CHECK_STR(name_at(t, 0x2500), "b");
    CHECK_STR(name_at(t, 0xfffffffffffffffeull), "c");
    cl_symtab_destroy(t);
}

static void test_malformed_maps(void)
{
    static const char junk[] =
        "zzzz T bad\n"
        "12345678901234567 T too_wide\n"
        "1000\n"
        "1000 T\n"
        "1000 XX name\n"
        "\n# comment\nlib.o:\n"
        "fffffffffffffff0 ffffffffffffffff T wraps\n";
    cl_symtab_t *t = cl_symtab_create();
    const cl_symbol_t *s;

    CHECK_INT(cl_symtab_load_buffer(t, junk, sizeof(junk) - 1), 0);
    CHECK_INT(cl_symtab_count(t), 1);
    CHECK_INT(cl_symtab_bad_lines(t), 5);
    s = cl_symtab_lookup(t, 0xfffffffffffffffeull);
    CHECK(s != NULL && s->end == 0xffffffffffffffffull);
    CHECK(cl_symtab_lookup(t, 0) == NULL);
    cl_symtab_destroy(t);

    t = cl_symtab_create();
    CHECK_INT(cl_symtab_load_buffer(t, "", 0), 0);
    CHECK(cl_symtab_lookup(t, 0x1000) == NULL);
    CHECK_INT(cl_symtab_load_file(t, "/nonexistent/map.sym"), -1);
    cl_symtab_destroy(t);
}

typedef struct {
    const cl_symtab_t *symtab;
    cl_fp_options_t    fp;
    uint64_t           fingerprints[4];
    cl_crash_event_t   first;
    size_t             count;
} symbolicate_ctx_t;

static int symbolicate_and_record(cl_crash_event_t *ev, void *arg)
{
    symbolicate_ctx_t *ctx = arg;

    CHECK_INT(cl_symbolicate(ctx->symtab, ev, LOAD_BIAS), 4);
    if (ctx->count == 0)
        ctx->first = *ev;
    if (ctx->count < 4)
        ctx->fingerprints[ctx->count] = cl_fingerprint(ev, &ctx->fp);
    ctx->count++;
    return 0;
}

/* Two runs of the same bug at different addresses only cluster together
 * once their frames have names. */
static void test_symbolicated_crashes_cluster(void)
{
    symbolicate_ctx_t *ctx = calloc(1, sizeof(*ctx));
    cl_parser_t *p = cl_parser_create(CL_FORMAT_AUTO, symbolicate_and_record, ctx);
    const cl_frame_t *f;
    char path[512];
    char sig[256];

    ctx->symtab = load_fixture();
    cl_fp_options_default(&ctx->fp);
    snprintf(path, sizeof(path), "%s/unsymbolicated.log", TEST_DATA_DIR);
    CHECK_INT(cl_parser_parse_file(p, path), CL_PARSE_OK);
    CHECK_INT(ctx->count, 2);
    CHECK_U64(ctx->fingerprints[0], ctx->fingerprints[1]);

    f = &ctx->first.frames[0];
    CHECK_STR(f->symbol, "parse_header");
    CHECK_U64(f->offset, 0x20);
    CHECK(f->flags & CL_FRAME_SYMBOLICATED);
    CHECK_STR(f->file, "/src/indexer/codec.c");
    CHECK_INT(f->line, 101);

    cl_fingerprint_signature(&ctx->first, &ctx->fp, sig, sizeof(sig));
    CHECK_STR(sig, "parse_header|decode_frame|segment_load|worker_main(Worker&, int)");

    cl_parser_destroy(p);
    cl_symtab_destroy((cl_symtab_t *)ctx->symtab);
    free(ctx);
}

static void test_symbolicate_skips(void)
{
    static cl_crash_event_t ev;
    cl_symtab_t *t = load_fixture();
    cl_frame_t *f;

    cl_event_reset(&ev);
    f = cl_event_push_frame(&ev);           /* already named */
    strcpy(f->symbol, "keep_me");
    f->address = 0x401000;
    f->flags = CL_FRAME_HAS_ADDRESS;
    f = cl_event_push_frame(&ev);           /* no address */
    f = cl_event_push_frame(&ev);           /* module-relative */
    f->address = 0x401000;
    f->flags = CL_FRAME_HAS_ADDRESS | CL_FRAME_MODULE_RELATIVE;
    f = cl_event_push_frame(&ev);           /* below the load bias */
    f->address = 0x10;
    f->flags = CL_FRAME_HAS_ADDRESS;

    CHECK_INT(cl_symbolicate(t, &ev, 0x100), 0);
    CHECK_STR(ev.frames[0].symbol, "keep_me");
    CHECK_STR(ev.frames[2].symbol, "");
    cl_symtab_destroy(t);
}

const test_case_t symbols_tests[] = {
    { "load_and_lookup", test_load_and_lookup },
    { "merge_recomputes_extents", test_merge_recomputes_extents },
    { "malformed_maps", test_malformed_maps },
    { "symbolicated_crashes_cluster", test_symbolicated_crashes_cluster },
    { "symbolicate_skips", test_symbolicate_skips },
    { NULL, NULL },
};
