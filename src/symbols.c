#include "crashlens/symbols.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "parser_internal.h"
#include "util.h"

struct cl_symtab {
    cl_symbol_t *syms;
    size_t       count;
    size_t       capacity;
    size_t       bad_lines;
};

cl_symtab_t *cl_symtab_create(void)
{
    return calloc(1, sizeof(cl_symtab_t));
}

void cl_symtab_destroy(cl_symtab_t *t)
{
    size_t i;

    if (!t)
        return;
    for (i = 0; i < t->count; i++) {
        free((char *)t->syms[i].name);
        free((char *)t->syms[i].file);
    }
    free(t->syms);
    free(t);
}

size_t cl_symtab_count(const cl_symtab_t *t)
{
    return t->count;
}

size_t cl_symtab_bad_lines(const cl_symtab_t *t)
{
    return t->bad_lines;
}

static int is_code_type(char type)
{
    return type == 'T' || type == 't' || type == 'W' || type == 'w' || type == 'i';
}

static int is_type_char(char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '?' || c == '-';
}

/* A whitespace-delimited token within [s, end). */
static const char *next_token(const char *s, const char *end, const char **tok_end)
{
    while (s < end && (*s == ' ' || *s == '\t'))
        s++;
    *tok_end = s;
    while (*tok_end < end && **tok_end != ' ' && **tok_end != '\t')
        (*tok_end)++;
    return s;
}

static int parse_hex_range(const char *s, const char *end, uint64_t *out)
{
    uint64_t v = 0;

    if (s == end || end - s > 16)
        return -1;
    for (; s < end; s++) {
        int c = (unsigned char)*s;

        if (!cl_isxdigit(c))
            return -1;
        v = v << 4 | (uint64_t)(cl_isdigit(c) ? c - '0' : (c | 0x20) - 'a' + 10);
    }
    *out = v;
    return 0;
}

static int push_symbol(cl_symtab_t *t, const cl_symbol_t *sym)
{
    if (t->count == t->capacity) {
        size_t cap = t->capacity ? t->capacity * 2 : 256;
        cl_symbol_t *grown;

        if (cap > SIZE_MAX / sizeof(*grown))
            return -1;
        grown = realloc(t->syms, cap * sizeof(*grown));
        if (!grown)
            return -1;
        t->syms = grown;
        t->capacity = cap;
    }
    t->syms[t->count++] = *sym;
    return 0;
}

static char *dup_range(const char *s, const char *end)
{
    size_t n = (size_t)(end - s);
    char *copy = malloc(n + 1);

    if (copy) {
        memcpy(copy, s, n);
        copy[n] = '\0';
    }
    return copy;
}

/* Returns 0 if the line was used or deliberately skipped, 1 if it is
 * malformed and -1 on allocation failure. */
static int parse_line(cl_symtab_t *t, const char *s, const char *end)
{
    const char *t0, *t0e, *t1, *t1e, *t2, *t2e, *name, *name_end, *tab;
    cl_symbol_t sym;
    uint64_t size = 0;
    char type;
    cl_frame_t loc;

    while (end > s && cl_isspace((unsigned char)end[-1]))
        end--;
    t0 = next_token(s, end, &t0e);
    if (t0 == end || *t0 == '#' || (t0e == end && t0e[-1] == ':'))
        return 0;
    /* "         U printf": undefined, no address. */
    if (t0e - t0 == 1 && is_type_char(*t0))
        return 0;
    if (parse_hex_range(t0, t0e, &sym.start) != 0)
        return 1;

    t1 = next_token(t0e, end, &t1e);
    t2 = next_token(t1e, end, &t2e);
    if (t1e - t1 == 1 && is_type_char(*t1) && !(t2e - t2 == 1 && is_type_char(*t2) &&
                                                t2e < end)) {
        type = *t1;
        name = t2;
    } else if (t2e - t2 == 1 && is_type_char(*t2) && parse_hex_range(t1, t1e, &size) == 0) {
        type = *t2;
        name = next_token(t2e, end, &name_end);
    } else {
        return 1;
    }

    /* The name runs to a tab (nm -l location) or the end of the line; it
     * may contain spaces when demangled. */
    if (name >= end)
        return 1;
    tab = memchr(name, '\t', (size_t)(end - name));
    name_end = tab ? tab : end;
    while (name_end > name && cl_isspace((unsigned char)name_end[-1]))
        name_end--;
    if (name_end == name)
        return 1;

    sym.size = size;
    sym.end = 0; /* set by finalize() */
    sym.is_code = is_code_type(type);
    sym.file = NULL;
    sym.line = 0;
    sym.name = dup_range(name, name_end);
    if (!sym.name)
        return -1;

    if (tab) {
        const char *loc_start = cl_skip_space(tab + 1);

        memset(&loc, 0, sizeof(loc));
        if (loc_start < end && cl_split_file_line(loc_start, end, &loc) == 0) {
            sym.file = cl_strdup(loc.file);
            sym.line = loc.line;
            if (!sym.file) {
                free((char *)sym.name);
                return -1;
            }
        }
    }

    if (push_symbol(t, &sym) != 0) {
        free((char *)sym.name);
        free((char *)sym.file);
        return -1;
    }
    return 0;
}

/* Sort by address; at equal addresses code symbols come first so they
 * win lookups over data or absolute symbols at the same spot. */
static int symbol_cmp(const void *pa, const void *pb)
{
    const cl_symbol_t *a = pa, *b = pb;

    if (a->start != b->start)
        return a->start < b->start ? -1 : 1;
    if (a->is_code != b->is_code)
        return a->is_code ? -1 : 1;
    return strcmp(a->name, b->name);
}

/* Sorts the table and derives each symbol's extent: its own size when the
 * map gave one, otherwise up to the next higher address. Rerun after every
 * load, since merged maps can change the neighbours. */
static void finalize(cl_symtab_t *t)
{
    uint64_t next_start = UINT64_MAX;
    size_t i;

    if (t->count == 0)
        return; /* t->syms may be NULL, which qsort does not accept */
    qsort(t->syms, t->count, sizeof(*t->syms), symbol_cmp);
    for (i = t->count; i-- > 0;) {
        cl_symbol_t *s = &t->syms[i];

        if (i + 1 < t->count && t->syms[i + 1].start > s->start)
            next_start = t->syms[i + 1].start;
        if (s->size)
            s->end = s->size > UINT64_MAX - s->start ? UINT64_MAX : s->start + s->size;
        else
            s->end = next_start;
    }
}

int cl_symtab_load_buffer(cl_symtab_t *t, const char *data, size_t len)
{
    const char *p, *end;
    int rc = 0;

    if (len == 0)
        return 0; /* data may be NULL, and NULL + 0 is undefined */
    p = data;
    end = data + len;

    while (p < end) {
        const char *nl = memchr(p, '\n', (size_t)(end - p));
        const char *line_end = nl ? nl : end;
        int r = parse_line(t, p, line_end);

        if (r < 0) {
            rc = -1;
            break;
        }
        t->bad_lines += (size_t)r;
        p = nl ? nl + 1 : end;
    }
    finalize(t);
    return rc;
}

int cl_symtab_load_file(cl_symtab_t *t, const char *path)
{
    FILE *fp = fopen(path, "rb");
    char *buf = NULL;
    size_t len = 0, cap = 0, n;
    int rc;

    if (!fp)
        return -1;
    for (;;) {
        if (cap - len < 65536) {
            char *grown;

            cap = cap ? cap * 2 : 65536;
            grown = realloc(buf, cap);
            if (!grown) {
                free(buf);
                fclose(fp);
                return -1;
            }
            buf = grown;
        }
        n = fread(buf + len, 1, cap - len, fp);
        len += n;
        if (n == 0)
            break;
    }
    rc = ferror(fp) ? -1 : 0;
    fclose(fp);
    if (rc == 0)
        rc = cl_symtab_load_buffer(t, buf, len);
    free(buf);
    return rc;
}

const cl_symbol_t *cl_symtab_lookup(const cl_symtab_t *t, uint64_t addr)
{
    size_t lo = 0, hi = t->count;
    const cl_symbol_t *s;

    /* First symbol whose start is above addr. */
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;

        if (t->syms[mid].start <= addr)
            lo = mid + 1;
        else
            hi = mid;
    }
    if (lo == 0)
        return NULL;

    /* Step back to the preferred entry among those at the same start. */
    s = &t->syms[lo - 1];
    while (s > t->syms && s[-1].start == s->start)
        s--;
    return s->is_code && addr < s->end ? s : NULL;
}

size_t cl_symbolicate(const cl_symtab_t *t, cl_crash_event_t *ev, uint64_t load_bias)
{
    size_t i, resolved = 0;

    for (i = 0; i < ev->frame_count; i++) {
        cl_frame_t *f = &ev->frames[i];
        const cl_symbol_t *sym;
        uint64_t addr;

        if (f->symbol[0] != '\0' || !(f->flags & CL_FRAME_HAS_ADDRESS) ||
            (f->flags & CL_FRAME_MODULE_RELATIVE) || f->address < load_bias)
            continue;
        addr = f->address - load_bias;
        sym = cl_symtab_lookup(t, addr);
        if (!sym)
            continue;

        cl_strlcpy(f->symbol, sym->name, sizeof(f->symbol));
        f->offset = addr - sym->start;
        f->flags |= CL_FRAME_HAS_OFFSET | CL_FRAME_SYMBOLICATED;
        if (f->file[0] == '\0' && sym->file) {
            cl_strlcpy(f->file, sym->file, sizeof(f->file));
            f->line = sym->line;
        }
        resolved++;
    }
    return resolved;
}
