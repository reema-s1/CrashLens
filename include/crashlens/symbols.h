#ifndef CRASHLENS_SYMBOLS_H
#define CRASHLENS_SYMBOLS_H

#include <stddef.h>
#include <stdint.h>

#include "crashlens/crash_event.h"

#ifdef __cplusplus
extern "C" {
#endif

/* A symbol table loaded from `nm` output, for resolving frames that were
 * logged as bare addresses. Accepted line forms (as produced by
 * `nm -n`, `nm -nS` and `nm -nl`, optionally with -C):
 *
 *   ADDRESS TYPE NAME[<TAB>FILE:LINE]
 *   ADDRESS SIZE TYPE NAME[<TAB>FILE:LINE]
 *
 * Only code symbols (types T, t, W, w, i) resolve addresses; the others
 * still bound the extent of the preceding symbol when no size is given.
 * Undefined symbols, blank lines, '#' comments and "object.o:" headers are
 * skipped; anything else counts as a bad line. */

typedef struct {
    uint64_t    start;
    uint64_t    end;     /* exclusive; UINT64_MAX if unbounded */
    uint64_t    size;    /* as given by the map; 0 if none */
    const char *name;
    const char *file;    /* NULL if unknown */
    int         line;    /* 0 if unknown */
    int         is_code;
} cl_symbol_t;

typedef struct cl_symtab cl_symtab_t;

cl_symtab_t *cl_symtab_create(void);
void         cl_symtab_destroy(cl_symtab_t *t);

/* Both may be called repeatedly to merge several maps. Return 0, or -1 on
 * allocation (or, for files, read) failure. */
int cl_symtab_load_buffer(cl_symtab_t *t, const char *data, size_t len);
int cl_symtab_load_file(cl_symtab_t *t, const char *path);

size_t cl_symtab_count(const cl_symtab_t *t);
size_t cl_symtab_bad_lines(const cl_symtab_t *t);

/* The code symbol containing addr, or NULL. */
const cl_symbol_t *cl_symtab_lookup(const cl_symtab_t *t, uint64_t addr);

/* Resolves every frame that has an absolute address but no symbol, after
 * subtracting load_bias (the runtime load address of the image minus its
 * link-time address). Module-relative frames are left alone, since the
 * table is not tied to a particular module. Returns the number of frames
 * resolved. */
size_t cl_symbolicate(const cl_symtab_t *t, cl_crash_event_t *ev, uint64_t load_bias);

#ifdef __cplusplus
}
#endif

#endif
