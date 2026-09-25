/* A small mutation-based driver for LLVMFuzzerTestOneInput targets, for
 * toolchains without libFuzzer (GCC, MSVC) and for bounded runs in CI.
 *
 *   fuzz_parser [-n ITERATIONS] [-s SEED] [-m MAX_LEN] [SEED_FILE...]
 *   fuzz_parser -r INPUT_FILE          # replay one input
 *
 * Every iteration is derived from (seed, iteration number) alone, so a run
 * is reproducible. If the target crashes, the offending input is written
 * to crash-<seed>-<iteration>.bin before the process dies. */

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

#define DEFAULT_MAX_LEN 65536

typedef struct {
    uint8_t *data;
    size_t   size;
} blob_t;

static const char *const dictionary[] = {
    "=== CRASH ===\n", "=== END ===\n", "Backtrace:\n", "Time: ", "Process: ",
    "Thread: ", "Signal: ", "Exception: ", "PID: ", "#0 0x", "#1 0x", " + ",
    " + 0x", "(a.c:1)", ":4294967296", "??", "\r\n", "\xEF\xBB\xBF", "\xFF\xFE",
    "\xFE\xFF", "==1==ERROR: AddressSanitizer: ", "LeakSanitizer: ", " in ",
    " (lib.so+0x10)", " (BuildId: ab)", "SUMMARY:", "==1==ABORTING", "thread T",
    "2026-09-25T14:03:11Z", "+23:59", "0000000000401000 T ", "\tfile.c:1",
    "ffffffffffffffff ", "0xffffffffffffffff", ".isra.0", " [clone .cold]",
};

/* Current input, for the crash handler. */
static const uint8_t *current_data;
static size_t current_size;
static unsigned long long current_seed, current_iter;

static void dump_current(void)
{
    char name[96];
    FILE *fp;

    if (!current_data)
        return;
    snprintf(name, sizeof(name), "crash-%llu-%llu.bin", current_seed, current_iter);
    fp = fopen(name, "wb");
    if (fp) {
        fwrite(current_data, 1, current_size, fp);
        fclose(fp);
        fprintf(stderr, "fuzz: failing input written to %s\n", name);
    }
    current_data = NULL;
}

static void on_signal(int sig)
{
    dump_current();
    signal(sig, SIG_DFL);
    raise(sig);
}

#if defined(__has_feature)
#if __has_feature(address_sanitizer)
#define HAVE_ASAN 1
#endif
#endif
#if defined(__SANITIZE_ADDRESS__)
#define HAVE_ASAN 1
#endif

#ifdef HAVE_ASAN
void __sanitizer_set_death_callback(void (*callback)(void));
#endif

static void run(const uint8_t *data, size_t size)
{
    current_data = data;
    current_size = size;
    LLVMFuzzerTestOneInput(data, size);
    current_data = NULL;
}

/* xorshift64* */
static uint64_t next_random(uint64_t *state)
{
    uint64_t x = *state;

    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    *state = x;
    return x * 0x2545F4914F6CDD1Dull;
}

static size_t below(uint64_t *rng, size_t n)
{
    return n ? (size_t)(next_random(rng) % n) : 0;
}

static int read_file(const char *path, blob_t *out)
{
    FILE *fp = fopen(path, "rb");
    long len;

    if (!fp)
        return -1;
    if (fseek(fp, 0, SEEK_END) != 0 || (len = ftell(fp)) < 0 || fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return -1;
    }
    out->size = (size_t)len;
    out->data = malloc(out->size ? out->size : 1);
    if (!out->data || fread(out->data, 1, out->size, fp) != out->size) {
        free(out->data);
        fclose(fp);
        return -1;
    }
    fclose(fp);
    return 0;
}

/* Replaces [pos, pos+del) with `ins` of length n, within max_len. */
static void splice_bytes(uint8_t *buf, size_t *len, size_t max_len, size_t pos,
                         size_t del, const uint8_t *ins, size_t n)
{
    size_t tail;

    if (pos > *len)
        pos = *len;
    if (del > *len - pos)
        del = *len - pos;
    if (*len - del + n > max_len)
        n = max_len - (*len - del);
    tail = *len - pos - del;
    memmove(buf + pos + n, buf + pos + del, tail);
    if (n > 0)
        memcpy(buf + pos, ins, n);
    *len = *len - del + n;
}

static void mutate(uint8_t *buf, size_t *len, size_t max_len, uint64_t *rng,
                   const blob_t *seeds, size_t nseeds)
{
    static const uint8_t interesting[] = { 0, 0xff, 0x7f, 0x80, '\n', '\r', ' ',
                                           '\t', '#', '(', ')', ':', '+', '=', '?' };
    uint8_t tmp[256];
    size_t pos = below(rng, *len + 1);
    size_t n;

    switch (below(rng, 9)) {
    case 0: /* flip a bit */
        if (*len)
            buf[below(rng, *len)] ^= (uint8_t)(1u << below(rng, 8));
        break;
    case 1: /* random byte */
        if (*len)
            buf[below(rng, *len)] = (uint8_t)next_random(rng);
        break;
    case 2: /* interesting byte */
        if (*len)
            buf[below(rng, *len)] = interesting[below(rng, sizeof(interesting))];
        break;
    case 3: /* dictionary token */
    {
        const char *tok = dictionary[below(rng, sizeof(dictionary) / sizeof(dictionary[0]))];

        splice_bytes(buf, len, max_len, pos, 0, (const uint8_t *)tok, strlen(tok));
        break;
    }
    case 4: /* delete a range */
        splice_bytes(buf, len, max_len, pos, below(rng, 64) + 1, NULL, 0);
        break;
    case 5: /* duplicate a range */
        if (*len) {
            size_t from = below(rng, *len);

            n = below(rng, sizeof(tmp)) + 1;
            if (n > *len - from)
                n = *len - from;
            memcpy(tmp, buf + from, n);
            splice_bytes(buf, len, max_len, pos, 0, tmp, n);
        }
        break;
    case 6: /* long run of one byte, to hit line-length limits */
        n = below(rng, 6000) + 1;
        while (n > 0) {
            size_t chunk = n < sizeof(tmp) ? n : sizeof(tmp);

            memset(tmp, interesting[below(rng, sizeof(interesting))], chunk);
            splice_bytes(buf, len, max_len, pos, 0, tmp, chunk);
            n -= chunk;
        }
        break;
    case 7: /* truncate */
        *len = pos;
        break;
    default: /* splice in part of another seed */
        if (nseeds) {
            const blob_t *other = &seeds[below(rng, nseeds)];

            if (other->size) {
                size_t from = below(rng, other->size);

                n = below(rng, 512) + 1;
                if (n > other->size - from)
                    n = other->size - from;
                splice_bytes(buf, len, max_len, pos, below(rng, 16), other->data + from, n);
            }
        }
        break;
    }
}

static unsigned long long parse_ull(const char *s)
{
    return strtoull(s, NULL, 10);
}

int main(int argc, char **argv)
{
    unsigned long long iterations = 10000, seed = 1, i;
    size_t max_len = DEFAULT_MAX_LEN;
    blob_t *seeds;
    size_t nseeds = 0;
    uint8_t *buf;
    int a;

    signal(SIGABRT, on_signal);
    signal(SIGSEGV, on_signal);
    signal(SIGFPE, on_signal);
    signal(SIGILL, on_signal);
#ifdef HAVE_ASAN
    __sanitizer_set_death_callback(dump_current);
#endif

    seeds = calloc((size_t)argc + 1, sizeof(*seeds));
    if (!seeds)
        return 2;

    for (a = 1; a < argc; a++) {
        if (strcmp(argv[a], "-n") == 0 && a + 1 < argc) {
            iterations = parse_ull(argv[++a]);
        } else if (strcmp(argv[a], "-s") == 0 && a + 1 < argc) {
            seed = parse_ull(argv[++a]);
        } else if (strcmp(argv[a], "-m") == 0 && a + 1 < argc) {
            max_len = (size_t)parse_ull(argv[++a]);
        } else if (strcmp(argv[a], "-r") == 0 && a + 1 < argc) {
            blob_t in;

            if (read_file(argv[++a], &in) != 0) {
                fprintf(stderr, "fuzz: cannot read %s\n", argv[a]);
                return 2;
            }
            run(in.data, in.size);
            printf("fuzz: replayed %s (%lu bytes) without failure\n", argv[a],
                   (unsigned long)in.size);
            free(in.data);
            return 0;
        } else if (read_file(argv[a], &seeds[nseeds]) == 0) {
            nseeds++;
        } else {
            fprintf(stderr, "fuzz: cannot read %s\n", argv[a]);
            return 2;
        }
    }
    if (max_len < 16)
        max_len = 16;

    buf = malloc(max_len);
    if (!buf)
        return 2;

    current_seed = seed;
    for (i = 0; i < nseeds; i++) {
        current_iter = i;
        run(seeds[i].data, seeds[i].size);
    }
    run(NULL, 0);

    for (i = 0; i < iterations; i++) {
        uint64_t rng = (seed + 1) * 0x9E3779B97F4A7C15ull ^ (i + 1) * 0xBF58476D1CE4E5B9ull;
        size_t len = 0;
        int k, rounds;

        if (rng == 0)
            rng = 1;
        if (nseeds) {
            const blob_t *s = &seeds[below(&rng, nseeds)];

            len = s->size < max_len ? s->size : max_len;
            memcpy(buf, s->data, len);
        }
        rounds = 1 + (int)below(&rng, 8);
        for (k = 0; k < rounds; k++)
            mutate(buf, &len, max_len, &rng, seeds, nseeds);

        current_iter = nseeds + i;
        run(buf, len);
    }

    printf("fuzz: %llu inputs (%lu seeds + %llu mutations, seed %llu), no failures\n",
           (unsigned long long)nseeds + iterations, (unsigned long)nseeds, iterations, seed);
    for (i = 0; i < nseeds; i++)
        free(seeds[i].data);
    free(seeds);
    free(buf);
    return 0;
}
