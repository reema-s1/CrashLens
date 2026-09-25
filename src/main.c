#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif

#include "crashlens/cluster.h"
#include "crashlens/fingerprint.h"
#include "crashlens/parser.h"
#include "crashlens/report.h"
#include "crashlens/symbols.h"
#include "fs.h"
#include "util.h"

enum {
    EXIT_OK = 0,
    EXIT_INPUT = 1,     /* some inputs could not be read */
    EXIT_USAGE = 2,
    EXIT_INTERNAL = 3   /* out of memory or output write failure */
};

typedef struct {
    cl_log_format_t     format;
    cl_report_options_t report;
    int                 json;
    int                 recursive;
    int                 verbose;
    const char         *output;
    const char        **symbol_files;   /* room for argc entries */
    int                 nsymbol_files;
    uint64_t            load_bias;
} options_t;

typedef struct {
    cl_cluster_table_t    *clusters;
    const cl_fp_options_t *fp;
    const cl_symtab_t     *symtab;      /* NULL when no maps were given */
    uint64_t               load_bias;
    uint64_t               symbolicated;
    int                    out_of_memory;
} pipeline_t;

static const char usage_text[] =
    "usage: crashlens [options] PATH...\n"
    "\n"
    "Parses crash reports from log files, groups crashes with the same\n"
    "normalised stack into clusters and prints a ranked triage report.\n"
    "PATH may be a file, a directory, or '-' for standard input.\n"
    "\n"
    "options:\n"
    "  -f, --format FMT     input format: auto (default), native, sanitizer\n"
    "  -n, --frames N       frames used for fingerprinting (default 5, 0 = all)\n"
    "      --keep-noise     keep crash-handler frames (abort, raise, ...) in\n"
    "                       the fingerprint\n"
    "  -s, --symbols FILE   resolve bare addresses with an nm-style symbol map\n"
    "                       (nm -nSl output); may be repeated\n"
    "      --load-bias ADDR subtract ADDR (hex) from addresses before lookup\n"
    "  -j, --json           write the report as JSON\n"
    "  -t, --top K          only report the K largest clusters\n"
    "  -d, --depth N        frames shown per example trace (default 12, 0 = all)\n"
    "  -r, --recursive      descend into subdirectories\n"
    "  -o, --output FILE    write the report to FILE instead of stdout\n"
    "  -v, --verbose        print per-file statistics to stderr\n"
    "  -V, --version        print the version and exit\n"
    "  -h, --help           print this help and exit\n"
    "\n"
    "exit status: 0 success, 1 unreadable input, 2 usage error, 3 internal error\n";

typedef enum {
    OPT_HELP, OPT_VERSION, OPT_FORMAT, OPT_FRAMES, OPT_KEEP_NOISE, OPT_JSON,
    OPT_TOP, OPT_DEPTH, OPT_RECURSIVE, OPT_OUTPUT, OPT_VERBOSE, OPT_SYMBOLS,
    OPT_LOAD_BIAS
} opt_id_t;

static const struct {
    opt_id_t    id;
    const char *shortname;  /* may be NULL */
    const char *longname;
    int         takes_value;
} option_table[] = {
    { OPT_HELP,       "-h", "--help",       0 },
    { OPT_VERSION,    "-V", "--version",    0 },
    { OPT_FORMAT,     "-f", "--format",     1 },
    { OPT_FRAMES,     "-n", "--frames",     1 },
    { OPT_KEEP_NOISE, NULL, "--keep-noise", 0 },
    { OPT_JSON,       "-j", "--json",       0 },
    { OPT_TOP,        "-t", "--top",        1 },
    { OPT_DEPTH,      "-d", "--depth",      1 },
    { OPT_RECURSIVE,  "-r", "--recursive",  0 },
    { OPT_OUTPUT,     "-o", "--output",     1 },
    { OPT_VERBOSE,    "-v", "--verbose",    0 },
    { OPT_SYMBOLS,    "-s", "--symbols",    1 },
    { OPT_LOAD_BIAS,  NULL, "--load-bias",  1 },
};

static int on_event(cl_crash_event_t *ev, void *ctx)
{
    pipeline_t *pl = ctx;

    if (pl->symtab)
        pl->symbolicated += cl_symbolicate(pl->symtab, ev, pl->load_bias);
    if (cl_cluster_table_add(pl->clusters, ev, cl_fingerprint(ev, pl->fp)) != 0) {
        pl->out_of_memory = 1;
        return 1;
    }
    return 0;
}

static int parse_count(const char *s, size_t limit, size_t *out)
{
    uint64_t v;

    if (cl_parse_u64(&s, 10, &v) != 0 || *s != '\0' || v > limit)
        return -1;
    *out = (size_t)v;
    return 0;
}

static int apply_option(opt_id_t id, const char *value, options_t *o)
{
    size_t n;

    switch (id) {
    case OPT_HELP:
        fputs(usage_text, stdout);
        exit(EXIT_OK);
    case OPT_VERSION:
        printf("crashlens %s\n", CRASHLENS_VERSION);
        exit(EXIT_OK);
    case OPT_FORMAT:
        return cl_format_from_name(value, &o->format);
    case OPT_FRAMES:
        if (parse_count(value, CL_MAX_STACK_DEPTH, &n) != 0)
            return -1;
        o->report.fp.top_n = (int)n;
        return 0;
    case OPT_KEEP_NOISE:
        o->report.fp.skip_noise = 0;
        return 0;
    case OPT_JSON:
        o->json = 1;
        return 0;
    case OPT_TOP:
        return parse_count(value, 1000000, &o->report.max_clusters);
    case OPT_DEPTH:
        return parse_count(value, CL_MAX_STACK_DEPTH, &o->report.max_frames);
    case OPT_RECURSIVE:
        o->recursive = 1;
        return 0;
    case OPT_OUTPUT:
        o->output = value;
        return 0;
    case OPT_VERBOSE:
        o->verbose = 1;
        return 0;
    case OPT_SYMBOLS:
        o->symbol_files[o->nsymbol_files++] = value;
        return 0;
    case OPT_LOAD_BIAS:
        return cl_parse_u64(&value, 16, &o->load_bias) == 0 && *value == '\0' ? 0 : -1;
    }
    return -1;
}

/* Accepts "-x VALUE", "--long VALUE" and "--long=VALUE". Options and paths
 * may be interleaved and "--" ends option parsing. Paths are stored, in
 * order, into `paths`, which must have room for argc entries. */
static int parse_args(int argc, char **argv, options_t *o, char **paths, int *npaths)
{
    int only_paths = 0;
    int i;

    *npaths = 0;
    for (i = 1; i < argc; i++) {
        const char *arg = argv[i];
        const char *value = NULL;
        size_t k;

        if (only_paths || arg[0] != '-' || strcmp(arg, "-") == 0) {
            paths[(*npaths)++] = argv[i];
            continue;
        }
        if (strcmp(arg, "--") == 0) {
            only_paths = 1;
            continue;
        }

        for (k = 0; k < CL_ARRAY_LEN(option_table); k++) {
            const char *s = option_table[k].shortname;
            const char *l = option_table[k].longname;
            size_t len = strlen(l);

            if ((s && strcmp(arg, s) == 0) || strcmp(arg, l) == 0)
                break;
            if (strncmp(arg, l, len) == 0 && arg[len] == '=') {
                value = arg + len + 1;
                break;
            }
        }
        if (k == CL_ARRAY_LEN(option_table)) {
            fprintf(stderr, "crashlens: unknown option '%s'\n", arg);
            return -1;
        }

        if (!option_table[k].takes_value && value) {
            fprintf(stderr, "crashlens: option '%s' takes no value\n",
                    option_table[k].longname);
            return -1;
        }
        if (option_table[k].takes_value && !value) {
            if (i + 1 >= argc) {
                fprintf(stderr, "crashlens: option '%s' needs a value\n", arg);
                return -1;
            }
            value = argv[++i];
        }
        if (apply_option(option_table[k].id, value, o) != 0) {
            fprintf(stderr, "crashlens: invalid value '%s' for '%s'\n", value,
                    option_table[k].longname);
            return -1;
        }
    }
    return 0;
}

static int parse_stdin(cl_parser_t *p)
{
    static char buf[64 * 1024];
    size_t n;
    int rc;

#ifdef _WIN32
    /* Text mode would stop at the first 0x1A byte and rewrite CRLFs. */
    _setmode(0, _O_BINARY);
#endif
    cl_parser_begin(p, "<stdin>");
    while ((n = fread(buf, 1, sizeof(buf), stdin)) > 0)
        if (cl_parser_feed(p, buf, n) == CL_PARSE_STOPPED)
            break;
    rc = cl_parser_finish(p);
    return ferror(stdin) ? CL_PARSE_IO : rc;
}

/* Expands the command-line paths into the list of inputs to read. */
static int collect_inputs(char **paths, int npaths, const options_t *o,
                          cl_pathlist_t *inputs, size_t *missing)
{
    int i;

    for (i = 0; i < npaths; i++) {
        int is_dir = strcmp(paths[i], "-") == 0 ? 0 : cl_fs_is_dir(paths[i]);
        char *copy;

        if (is_dir < 0) {
            fprintf(stderr, "crashlens: %s: %s\n", paths[i], strerror(errno));
            (*missing)++;
            continue;
        }
        if (is_dir) {
            size_t before = inputs->count;

            if (cl_fs_list_files(paths[i], o->recursive, inputs) != 0) {
                fprintf(stderr, "crashlens: %s: cannot read directory\n", paths[i]);
                (*missing)++;
            } else if (inputs->count == before && o->verbose) {
                fprintf(stderr, "crashlens: %s: no files\n", paths[i]);
            }
            continue;
        }
        copy = cl_strdup(paths[i]);
        if (!copy || cl_pathlist_push(inputs, copy) != 0) {
            free(copy);
            return -1;
        }
    }
    return 0;
}

static void parse_inputs(cl_parser_t *parser, const cl_pathlist_t *inputs,
                         const options_t *o, const pipeline_t *pl, size_t *unreadable)
{
    size_t i;

    for (i = 0; i < inputs->count && !pl->out_of_memory; i++) {
        const char *path = inputs->paths[i];
        cl_parse_stats_t before = *cl_parser_stats(parser);
        const cl_parse_stats_t *after;
        int rc;

        errno = 0;
        rc = strcmp(path, "-") == 0 ? parse_stdin(parser)
                                    : cl_parser_parse_file(parser, path);
        if (rc == CL_PARSE_IO) {
            fprintf(stderr, "crashlens: %s: %s\n", path,
                    errno ? strerror(errno) : "read error");
            (*unreadable)++;
            continue;
        }
        after = cl_parser_stats(parser);
        if (o->verbose)
            fprintf(stderr, "crashlens: %s: %llu crashes, %llu rejected, %llu lines\n",
                    path, (unsigned long long)(after->events - before.events),
                    (unsigned long long)(after->rejected - before.rejected),
                    (unsigned long long)(after->lines - before.lines));
    }
}

static int write_report(const options_t *o, const cl_cluster_table_t *clusters)
{
    FILE *out = stdout;
    int rc;

    if (o->output && !(out = fopen(o->output, "w"))) {
        fprintf(stderr, "crashlens: %s: %s\n", o->output, strerror(errno));
        return -1;
    }
    rc = o->json ? cl_report_json(out, clusters, &o->report)
                 : cl_report_text(out, clusters, &o->report);
    if (fflush(out) != 0)
        rc = -1;
    if (out != stdout && fclose(out) != 0)
        rc = -1;
    if (rc != 0)
        fputs("crashlens: failed to write the report\n", stderr);
    return rc;
}

/* A missing or unreadable map is fatal: the report would silently differ
 * from what was asked for. */
static int load_symbols(const options_t *o, cl_symtab_t **out)
{
    cl_symtab_t *t;
    int i;

    *out = NULL;
    if (o->nsymbol_files == 0)
        return 0;
    t = cl_symtab_create();
    if (!t)
        return -1;
    for (i = 0; i < o->nsymbol_files; i++) {
        size_t bad_before = cl_symtab_bad_lines(t);

        errno = 0;
        if (cl_symtab_load_file(t, o->symbol_files[i]) != 0) {
            fprintf(stderr, "crashlens: %s: cannot load symbols: %s\n",
                    o->symbol_files[i], errno ? strerror(errno) : "read error");
            cl_symtab_destroy(t);
            return -1;
        }
        if (o->verbose && cl_symtab_bad_lines(t) > bad_before) {
            size_t bad = cl_symtab_bad_lines(t) - bad_before;

            fprintf(stderr, "crashlens: %s: %u line%s not understood\n",
                    o->symbol_files[i], (unsigned)bad, bad == 1 ? "" : "s");
        }
    }
    if (o->verbose)
        fprintf(stderr, "crashlens: %u symbols loaded\n", (unsigned)cl_symtab_count(t));
    *out = t;
    return 0;
}

int main(int argc, char **argv)
{
    options_t o;
    pipeline_t pl;
    cl_pathlist_t inputs = { NULL, 0, 0 };
    cl_parser_t *parser = NULL;
    cl_symtab_t *symtab = NULL;
    char **paths;
    size_t missing = 0, unreadable = 0;
    int npaths = 0;
    int status = EXIT_OK;

    memset(&o, 0, sizeof(o));
    memset(&pl, 0, sizeof(pl));
    o.format = CL_FORMAT_AUTO;
    cl_report_options_default(&o.report);

    paths = malloc((size_t)argc * sizeof(*paths));
    o.symbol_files = malloc((size_t)argc * sizeof(*o.symbol_files));
    if (!paths || !o.symbol_files) {
        fputs("crashlens: out of memory\n", stderr);
        status = EXIT_INTERNAL;
        goto done;
    }
    if (parse_args(argc, argv, &o, paths, &npaths) != 0) {
        fputs("try 'crashlens --help'\n", stderr);
        status = EXIT_USAGE;
        goto done;
    }
    if (npaths == 0) {
        fputs(usage_text, stderr);
        status = EXIT_USAGE;
        goto done;
    }
    if (load_symbols(&o, &symtab) != 0) {
        status = EXIT_INPUT;
        goto done;
    }

    pl.fp = &o.report.fp;
    pl.symtab = symtab;
    pl.load_bias = o.load_bias;
    pl.clusters = cl_cluster_table_create();
    parser = cl_parser_create(o.format, on_event, &pl);
    if (!pl.clusters || !parser ||
        collect_inputs(paths, npaths, &o, &inputs, &missing) != 0) {
        fputs("crashlens: out of memory\n", stderr);
        status = EXIT_INTERNAL;
        goto done;
    }

    unreadable = missing;
    parse_inputs(parser, &inputs, &o, &pl, &unreadable);
    if (pl.out_of_memory) {
        fputs("crashlens: out of memory\n", stderr);
        status = EXIT_INTERNAL;
        goto done;
    }

    if (o.verbose && symtab)
        fprintf(stderr, "crashlens: %llu frames symbolicated\n",
                (unsigned long long)pl.symbolicated);

    o.report.stats = cl_parser_stats(parser);
    o.report.inputs = inputs.count + missing;
    o.report.unreadable = unreadable;
    if (write_report(&o, pl.clusters) != 0)
        status = EXIT_INTERNAL;
    else if (unreadable)
        status = EXIT_INPUT;

done:
    cl_pathlist_free(&inputs);
    free(paths);
    free(o.symbol_files);
    cl_parser_destroy(parser);
    cl_cluster_table_destroy(pl.clusters);
    cl_symtab_destroy(symtab);
    return status;
}
