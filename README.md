# CrashLens

CrashLens is a crash triage tool written in C. It reads crash reports out of
log files, fingerprints each crash by its normalised stack trace, and groups
crashes that share a root cause. Forty crash reports that are really three
bugs come back as three clusters, ranked by how often and how recently they
happened, each with one representative trace.

Here it is run on the test fixtures in this repository:

```
$ crashlens --symbols tests/data/indexer.sym --load-bias 0x555555400000 --top 2 -d 6 tests/data
CrashLens 0.1.0 triage report

  inputs     4 files, 5.0 KiB, 127 lines
  crashes    11 parsed (1 truncated), 1 rejected as unusable
  clusters   9 distinct from 11 crashes, top 5 frames, crash-handler frames skipped
  showing    top 2

#1  2 crashes (18.2%)  heap-use-after-free  fingerprint 7e8425a13c24fff8
    seen       2026-09-25T09:54:24Z  (1 file, times from file modification)
    signature  parse_header|decode_frame|Segment::load(std::string const&)|start_thread
    example    tests/data/sanitizer.log:3  pid 4121  thread T3
     * #0  0x000055555555d0c4  parse_header  (/src/indexer/codec.c:118)
     * #1  0x000055555555d1f0  decode_frame.isra.0  (/src/indexer/codec.c:201)
     * #2  0x000055555555e000  Segment::load(std::string const&)  (/src/indexer/segment.cc:40)
     * #3  0x00007f3a1c229d8f  start_thread  (libc.so.6+0x94ac3)

#2  2 crashes (18.2%)  SIGSEGV  fingerprint a4225b6ed583a820
    seen       2026-09-24T08:00:00Z .. 2026-09-24T09:30:00Z  (1 file)
    signature  parse_header|decode_frame|segment_load|worker_main(Worker&, int)
    example    tests/data/unsymbolicated.log:1  indexer  pid 311
     * #0  0x0000555555801320  parse_header + 0x20  (/src/indexer/codec.c:101)
     * #1  0x00005555558011a0  decode_frame.isra.0 + 0x40  (/src/indexer/codec.c:190)
     * #2  0x0000555555801050  segment_load + 0x10  (/src/indexer/segment.c:40)
     * #3  0x0000555555801410  worker_main(Worker&, int) + 0x10  (/src/indexer/worker.cc:70)
```

Frames marked `*` form the fingerprint. In cluster #1, the two sanitizer
reports came from different processes at different addresses, and one of
them logged a compiler clone (`.isra.0`), yet they cluster together. In
cluster #2, the frames were logged as bare addresses and resolved from the
symbol map.

## Features

- **Two input formats, detected per report:** a simple native block format
  and AddressSanitizer/LeakSanitizer output. Reports can be embedded in
  ordinary log output and both formats can appear in the same file.
- **Stable fingerprints:** crashes are identified by the function names in
  the top frames, not by addresses, offsets, PIDs or timestamps. The same
  bug therefore hashes the same way across runs, ASLR slides and rebuilds.
- **Symbolication:** frames logged as bare addresses can be resolved with a
  symbol map produced by `nm`.
- **Robust input handling:** truncated reports, garbage lines, overlong
  lines, embedded NULs, UTF-8/UTF-16 byte-order marks and CRLF endings are
  all handled. Bad input is counted and skipped; it never stops the run.
- **Text or JSON output:** the JSON report is always valid UTF-8, whatever
  bytes the logs contained.
- **Plain C11 with no dependencies.** Builds with GCC, Clang and MSVC.

## Building

```sh
cmake -S . -B build
cmake --build build
ctest --test-dir build        # unit, CLI, fuzz and accuracy tests
```

CMake options:

| Option | Default | |
|---|---|---|
| `CRASHLENS_BUILD_TESTS` | `ON` | unit tests, CLI tests, bounded fuzz runs |
| `CRASHLENS_BUILD_FUZZ` | `ON` | fuzz targets with the bundled mutation driver |
| `CRASHLENS_LIBFUZZER` | `OFF` | also build libFuzzer binaries (Clang) |
| `CRASHLENS_SANITIZE` | `OFF` | build everything with ASan + UBSan |
| `CRASHLENS_WERROR` | `OFF` | treat warnings as errors |
| `CRASHLENS_FUZZ_ITERATIONS` | `5000` | mutations per fuzz target under CTest |

## Usage

```
crashlens [options] PATH...
```

`PATH` can be a file, a directory, or `-` for standard input. Options and
paths can be mixed.

| Option | |
|---|---|
| `-f, --format FMT` | `auto` (default), `native` or `sanitizer` |
| `-n, --frames N` | frames used for the fingerprint (default 5, `0` = whole stack) |
| `--keep-noise` | keep crash-handler frames in the fingerprint |
| `-s, --symbols FILE` | resolve bare addresses with an `nm -nSl` symbol map (repeatable) |
| `--load-bias ADDR` | subtract this hex address before symbol lookup |
| `-j, --json` | JSON output |
| `-t, --top K` | show only the K largest clusters |
| `-d, --depth N` | frames shown per example trace (default 12, `0` = all) |
| `-r, --recursive` | descend into subdirectories |
| `-o, --output FILE` | write the report to a file |
| `-v, --verbose` | per-file statistics on stderr |

Exit status: `0` on success, `1` if some input could not be read (the report
is still written), `2` for a usage error, and `3` for an internal error.

### Symbolication

For crashes logged without function names, produce a map from the binary and
pass its load bias. The load bias is the runtime base address minus the
link-time base address:

```sh
nm -nSl --defined-only ./indexer > indexer.sym
crashlens --symbols indexer.sym --load-bias 0x555555400000 crashes/
```

Accepted map lines are `ADDR TYPE NAME` and `ADDR SIZE TYPE NAME`, each
optionally followed by a tab and `FILE:LINE`. Demangled names containing
spaces are fine. Only code symbols (`T t W w i`) resolve addresses. A symbol
without a size extends to the next symbol of any type, so an address inside
a data object is never attributed to the function before it.

## Input formats

### Native

```
=== CRASH ===
Time: 2026-09-25T14:03:11Z
Process: indexer [4121]
Thread: worker-3
Signal: SIGSEGV (11)
Exception: std::out_of_range
Backtrace:
  #0  0x00007f3a1c2b1c20 parse_header + 32 (codec.c:118)
  #1  0x00007f3a1c2b0010 decode_frame + 0x90
  #2  0x0000560d4e2a1f00 ??
=== END ===
```

Every header line is optional and unknown keys are ignored. `Signal:` accepts
a name, a number, or both. `Time:` is ISO 8601; a time without a zone is taken
as UTC. A frame is `#N 0xADDR SYMBOL [+ OFFSET] [(FILE:LINE)]`. C++ symbols
may contain spaces and parentheses. A report cut off by the end of input or
by the next report is kept and flagged as truncated.

### Sanitizer

Standard `==PID==ERROR: AddressSanitizer: <kind> ...` reports, including
LeakSanitizer. Only the faulting stack is used. The "freed by" and
"previously allocated" stacks describe other code paths and are skipped.
Frames without a symbol keep their `(module+0xoffset)` location, which is
also stable across ASLR runs.

Reports carry no timestamp. For those, the file's modification time is used
and the report says so.

## How fingerprinting works

1. **Skip crash machinery.** Leading frames such as `raise`, `abort`,
   `__assert_fail`, `__pthread_kill`, `__cxa_throw` and the sanitizer
   runtime describe how the process died, not where the bug is. If they
   counted, every assertion failure would share most of its signature.
   Disable this with `--keep-noise`.
2. **Take the top N frames** (default 5). This is deep enough to tell
   different bugs apart, and shallow enough that different callers of the
   same faulty code don't split one bug into many clusters.
3. **Normalise each frame to a token:** the function name with compiler
   clone suffixes removed (`.isra.0`, `.constprop.1`, `.cold`,
   ` [clone .cold]`). For an unsymbolised frame the token is
   `module+0xoffset` if the module is known, otherwise `??`. Addresses,
   offsets and line numbers are dropped.
4. **Hash** the `|`-joined tokens with 64-bit FNV-1a. The separator keeps
   `ab|c` and `a|bc` apart.

Clusters live in an open-addressing hash table keyed by fingerprint. Each
cluster records its count, first and last seen times, the number of source
files, and the most complete member as its example: the one with the most
symbolised frames and source locations. Clusters are ranked by count, then
by recency, then by fingerprint, so output is deterministic.

## Testing

- **Unit tests** cover the parsers (including byte-at-a-time feeding,
  UTF-16, CRLF, overlong lines and stack overflow), fingerprint stability
  and discrimination, clustering, reports (JSON escaping and UTF-8
  repair), symbol maps and the helpers.
- **Fuzzing.** `fuzz/fuzz_parser.c` and `fuzz/fuzz_symbols.c` are standard
  `LLVMFuzzerTestOneInput` targets. They run under libFuzzer with Clang,
  and under a bundled deterministic mutation driver everywhere else, with
  a dictionary of format tokens. Besides crashes and leaks, the parser
  target asserts that chunked and one-shot parsing agree, that every
  accepted event is consistent, and that each fingerprint matches its
  signature. A failing input is saved as `crash-<seed>-<iteration>.bin`;
  replay it with `fuzz_parser -r FILE`.
- **Sanitizers.** CI runs the whole suite under ASan + UBSan with 200k
  mutations per target. UBSan has already caught a `qsort(NULL, 0)` on
  empty symbol maps.
- **Accuracy benchmark.** `scale_bench` generates crash reports from a
  known set of bugs. Each report varies in PID, thread, time, ASLR slide,
  offsets, deeper callers, crash-handler frames, clone suffixes and format.
  Some bug pairs share their first three or four frames, and the reports
  are mixed with log noise, truncated reports and reports with no stack.
  The benchmark then measures throughput and how well each fingerprinting
  strategy recovers the bugs:

```
$ scale_bench --events 50000 --bugs 40
  input        56.4 MiB, 1229028 lines, 50000 crash reports from 40 bugs (seed 1)
  malformed    994 without a stack (rejected), 310 truncated (kept)
  throughput   74.0 MiB/s, 64305 crashes/s (parse + fingerprint + cluster, best of 5)

  fingerprint                       clusters   purity  completeness  exact bugs
  raw frames (address + symbol)        49006    1.000         0.001       0/40
  function names, whole stack          24444    1.000         0.501       0/40
  top 5 names, noise kept                 86    0.938         0.794       1/40
  top 5 names, noise skipped              40    1.000         1.000      40/40
```

Purity is the share of crashes that belong to their cluster's majority bug.
Completeness is the share of crashes that sit in their bug's largest
cluster. The throughput figure is from a 32-bit MinGW build and will vary
by machine.

## Library use

The CLI is a thin layer over a small library:

```c
#include "crashlens/cluster.h"
#include "crashlens/fingerprint.h"
#include "crashlens/parser.h"
#include "crashlens/report.h"

static int on_crash(cl_crash_event_t *ev, void *ctx)
{
    cl_fp_options_t fp;

    cl_fp_options_default(&fp);
    /* A nonzero return (here: out of memory) stops the parser. */
    return cl_cluster_table_add(ctx, ev, cl_fingerprint(ev, &fp));
}

int main(void)
{
    cl_cluster_table_t *clusters = cl_cluster_table_create();
    cl_parser_t *parser = cl_parser_create(CL_FORMAT_AUTO, on_crash, clusters);
    cl_report_options_t opts;

    cl_parser_parse_file(parser, "app.log");
    cl_report_options_default(&opts);
    opts.stats = cl_parser_stats(parser);
    cl_report_json(stdout, clusters, &opts);

    cl_parser_destroy(parser);
    cl_cluster_table_destroy(clusters);
    return 0;
}
```

The parser streams its input (`cl_parser_begin` / `cl_parser_feed` /
`cl_parser_finish`), so input size is bounded by disk, not memory.
Only one crash event and one representative per cluster are ever held.

## Layout

```
include/crashlens/   public headers
src/                 parser and format adapters, fingerprinting, clustering,
                     reports, symbol maps, CLI
tests/               unit tests and fixtures
fuzz/                fuzz targets, mutation driver, libFuzzer dictionary
bench/               synthetic scale and accuracy benchmark
```

## Limitations

- Symbol maps aren't tied to a module, so frames that already carry a
  `module+offset` location aren't symbolicated.
- Timestamps are parsed only from native reports; sanitizer reports use
  file modification times.
- Different bugs that share their top N frames are merged. Raise `--frames`
  when that happens.
