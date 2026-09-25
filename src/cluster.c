#include "crashlens/cluster.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "crashlens/fingerprint.h"

#define INITIAL_CAPACITY 64

/* Open addressing with linear probing, kept below 75% load. */
typedef struct {
    cl_cluster_t cluster;
    uint64_t     last_source;   /* hash of the most recent member's source */
    int          rep_score;
    int          used;
} slot_t;

struct cl_cluster_table {
    slot_t  *slots;
    size_t   capacity;          /* always a power of two */
    size_t   size;
    uint64_t total;
};

/* Fingerprints are hashes already, but a finaliser keeps probe sequences
 * short even if a caller supplies structured values. */
static uint64_t mix(uint64_t x)
{
    x ^= x >> 30;
    x *= 0xbf58476d1ce4e5b9ull;
    x ^= x >> 27;
    x *= 0x94d049bb133111ebull;
    x ^= x >> 31;
    return x;
}

static slot_t *probe(slot_t *slots, size_t capacity, uint64_t fp)
{
    size_t mask = capacity - 1;
    size_t i = (size_t)mix(fp) & mask;

    while (slots[i].used && slots[i].cluster.fingerprint != fp)
        i = (i + 1) & mask;
    return &slots[i];
}

cl_cluster_table_t *cl_cluster_table_create(void)
{
    cl_cluster_table_t *t = calloc(1, sizeof(*t));

    if (!t)
        return NULL;
    t->slots = calloc(INITIAL_CAPACITY, sizeof(*t->slots));
    if (!t->slots) {
        free(t);
        return NULL;
    }
    t->capacity = INITIAL_CAPACITY;
    return t;
}

void cl_cluster_table_destroy(cl_cluster_table_t *t)
{
    size_t i;

    if (!t)
        return;
    for (i = 0; i < t->capacity; i++)
        if (t->slots[i].used)
            free(t->slots[i].cluster.representative);
    free(t->slots);
    free(t);
}

static int grow(cl_cluster_table_t *t)
{
    size_t capacity = t->capacity * 2;
    slot_t *slots;
    size_t i;

    if (capacity < t->capacity || capacity > SIZE_MAX / sizeof(*slots))
        return -1;
    slots = calloc(capacity, sizeof(*slots));
    if (!slots)
        return -1;
    for (i = 0; i < t->capacity; i++)
        if (t->slots[i].used)
            *probe(slots, capacity, t->slots[i].cluster.fingerprint) = t->slots[i];
    free(t->slots);
    t->slots = slots;
    t->capacity = capacity;
    return 0;
}

/* How useful an event is as the example shown for its cluster. */
static int completeness(const cl_crash_event_t *ev)
{
    int score = 0;
    size_t i;

    for (i = 0; i < ev->frame_count; i++) {
        if (ev->frames[i].symbol[0] != '\0')
            score += 2;
        if (ev->frames[i].file[0] != '\0' && ev->frames[i].line > 0)
            score += 1;
    }
    if (ev->flags & CL_EVENT_TRUNCATED)
        score -= 1;
    return score;
}

/* Copies only the populated part of the frame array. */
static void copy_event(cl_crash_event_t *dst, const cl_crash_event_t *src)
{
    memcpy(dst, src, offsetof(cl_crash_event_t, frames) +
                     src->frame_count * sizeof(src->frames[0]));
}

int cl_cluster_table_add(cl_cluster_table_t *t, const cl_crash_event_t *ev,
                         uint64_t fingerprint)
{
    uint64_t source = cl_fnv1a64(ev->source, strlen(ev->source), CL_FNV1A64_INIT);
    slot_t *slot;
    cl_cluster_t *c;
    int score = completeness(ev);

    if ((t->size + 1) * 4 > t->capacity * 3 && grow(t) != 0)
        return -1;

    slot = probe(t->slots, t->capacity, fingerprint);
    c = &slot->cluster;
    if (!slot->used) {
        c->representative = malloc(sizeof(*c->representative));
        if (!c->representative)
            return -1;
        copy_event(c->representative, ev);
        c->fingerprint = fingerprint;
        c->count = 0;
        c->truncated = 0;
        c->estimated_times = 0;
        c->first_seen = 0;
        c->last_seen = 0;
        c->sources = 1;
        slot->last_source = source;
        slot->rep_score = score;
        slot->used = 1;
        t->size++;
    } else {
        /* Inputs are read one at a time, so a change of source between
         * consecutive members means a new file. */
        if (source != slot->last_source) {
            c->sources++;
            slot->last_source = source;
        }
        if (score > slot->rep_score) {
            copy_event(c->representative, ev);
            slot->rep_score = score;
        }
    }

    c->count++;
    if (ev->flags & CL_EVENT_TRUNCATED)
        c->truncated++;
    if (ev->flags & CL_EVENT_TIME_ESTIMATED)
        c->estimated_times++;
    if (ev->timestamp != 0) {
        if (c->first_seen == 0 || ev->timestamp < c->first_seen)
            c->first_seen = ev->timestamp;
        if (c->last_seen == 0 || ev->timestamp > c->last_seen)
            c->last_seen = ev->timestamp;
    }
    t->total++;
    return 0;
}

size_t cl_cluster_table_size(const cl_cluster_table_t *t)
{
    return t->size;
}

uint64_t cl_cluster_table_total(const cl_cluster_table_t *t)
{
    return t->total;
}

const cl_cluster_t *cl_cluster_table_find(const cl_cluster_table_t *t,
                                          uint64_t fingerprint)
{
    const slot_t *slot = probe(t->slots, t->capacity, fingerprint);

    return slot->used ? &slot->cluster : NULL;
}

static int rank_cmp(const void *pa, const void *pb)
{
    const cl_cluster_t *a = *(const cl_cluster_t *const *)pa;
    const cl_cluster_t *b = *(const cl_cluster_t *const *)pb;

    if (a->count != b->count)
        return a->count > b->count ? -1 : 1;
    if (a->last_seen != b->last_seen)
        return a->last_seen > b->last_seen ? -1 : 1;
    if (a->fingerprint != b->fingerprint)
        return a->fingerprint < b->fingerprint ? -1 : 1;
    return 0;
}

const cl_cluster_t **cl_cluster_table_ranked(const cl_cluster_table_t *t,
                                             size_t *count)
{
    const cl_cluster_t **ranked;
    size_t i, n = 0;

    *count = 0;
    if (t->size == 0)
        return NULL;
    ranked = malloc(t->size * sizeof(*ranked));
    if (!ranked)
        return NULL;
    for (i = 0; i < t->capacity; i++)
        if (t->slots[i].used)
            ranked[n++] = &t->slots[i].cluster;
    qsort(ranked, n, sizeof(*ranked), rank_cmp);
    *count = n;
    return ranked;
}
