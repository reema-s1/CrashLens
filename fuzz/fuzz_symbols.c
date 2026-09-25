/* Fuzz target: symbol map loading, lookup and symbolication. */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crashlens/symbols.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static void check(int ok, const char *what)
{
    if (!ok) {
        fprintf(stderr, "invariant violated: %s\n", what);
        abort();
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static cl_crash_event_t ev;
    cl_symtab_t *t = cl_symtab_create();
    size_t i;

    if (!t)
        abort();
    cl_symtab_load_buffer(t, (const char *)data, size);

    /* Probe with addresses taken from the input itself, so lookups land
     * on and around the symbols it declares. */
    cl_event_reset(&ev);
    for (i = 0; i + 8 <= size && i < 8 * 64; i += 8) {
        uint64_t addr = 0;
        const cl_symbol_t *s;
        cl_frame_t *f;
        size_t b;

        for (b = 0; b < 8; b++)
            addr = addr << 8 | data[i + b];
        s = cl_symtab_lookup(t, addr);
        if (s)
            check(s->is_code && s->start <= addr && addr < s->end, "lookup result contains address");

        f = cl_event_push_frame(&ev);
        if (f) {
            f->address = addr;
            f->flags = CL_FRAME_HAS_ADDRESS;
        }
    }
    cl_symbolicate(t, &ev, size > 0 ? data[0] : 0);
    for (i = 0; i < ev.frame_count; i++)
        check(memchr(ev.frames[i].symbol, '\0', sizeof(ev.frames[i].symbol)) != NULL,
              "symbol terminated");

    cl_symtab_destroy(t);
    return 0;
}
