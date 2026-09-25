#include <stdlib.h>
#include <string.h>

#include "crashlens/cluster.h"
#include "test.h"

static cl_crash_event_t *event(const char *source, int64_t ts, const char *top,
                               int with_lines)
{
    static cl_crash_event_t ev;
    cl_frame_t *f;

    cl_event_reset(&ev);
    strcpy(ev.source, source);
    strcpy(ev.kind, "SIGSEGV");
    ev.signal = 11;
    ev.timestamp = ts;
    ev.pid = 42;
    f = cl_event_push_frame(&ev);
    strcpy(f->symbol, top);
    f->address = 0x401000;
    f->flags = CL_FRAME_HAS_ADDRESS;
    if (with_lines) {
        strcpy(f->file, "a.c");
        f->line = 10;
    }
    f = cl_event_push_frame(&ev);
    strcpy(f->symbol, "main");
    return &ev;
}

static void test_counts_and_times(void)
{
    cl_cluster_table_t *t = cl_cluster_table_create();
    const cl_cluster_t *c;
    cl_crash_event_t *ev;

    CHECK_INT(cl_cluster_table_add(t, event("a.log", 300, "f", 0), 1), 0);
    ev = event("a.log", 100, "f", 0);
    ev->flags |= CL_EVENT_TIME_ESTIMATED;
    CHECK_INT(cl_cluster_table_add(t, ev, 1), 0);
    CHECK_INT(cl_cluster_table_add(t, event("b.log", 0, "f", 0), 1), 0);
    CHECK_INT(cl_cluster_table_add(t, event("b.log", 200, "g", 0), 2), 0);

    CHECK_INT(cl_cluster_table_size(t), 2);
    CHECK_INT(cl_cluster_table_total(t), 4);

    c = cl_cluster_table_find(t, 1);
    CHECK(c != NULL);
    if (c) {
        CHECK_INT(c->count, 3);
        CHECK_INT(c->first_seen, 100);
        CHECK_INT(c->last_seen, 300);
        CHECK_INT(c->sources, 2);
        CHECK_INT(c->estimated_times, 1);
    }
    CHECK(cl_cluster_table_find(t, 3) == NULL);
    cl_cluster_table_destroy(t);
}

static void test_representative_prefers_complete(void)
{
    cl_cluster_table_t *t = cl_cluster_table_create();
    const cl_cluster_t *c;

    cl_cluster_table_add(t, event("first.log", 1, "f", 0), 7);
    cl_cluster_table_add(t, event("rich.log", 2, "f", 1), 7);
    cl_cluster_table_add(t, event("later.log", 3, "f", 1), 7);

    c = cl_cluster_table_find(t, 7);
    CHECK(c != NULL);
    if (c) {
        CHECK_STR(c->representative->source, "rich.log");
        CHECK_INT(c->representative->frame_count, 2);
        CHECK_STR(c->representative->frames[1].symbol, "main");
    }
    cl_cluster_table_destroy(t);
}

static void test_ranking(void)
{
    cl_cluster_table_t *t = cl_cluster_table_create();
    const cl_cluster_t **ranked;
    size_t n = 0;
    int i;

    /* fp 10: 1 crash; fp 20: 3 crashes; fp 30 and 40: 2 crashes each, 40
     * more recent; fp 50 and 60: tie on count and time. */
    cl_cluster_table_add(t, event("x", 5, "a", 0), 10);
    for (i = 0; i < 3; i++)
        cl_cluster_table_add(t, event("x", 5, "b", 0), 20);
    for (i = 0; i < 2; i++)
        cl_cluster_table_add(t, event("x", 5, "c", 0), 30);
    for (i = 0; i < 2; i++)
        cl_cluster_table_add(t, event("x", 9, "d", 0), 40);
    cl_cluster_table_add(t, event("x", 5, "e", 0), 60);
    cl_cluster_table_add(t, event("x", 5, "f", 0), 50);

    ranked = cl_cluster_table_ranked(t, &n);
    CHECK_INT(n, 6);
    if (ranked && n == 6) {
        CHECK_U64(ranked[0]->fingerprint, 20);
        CHECK_U64(ranked[1]->fingerprint, 40);
        CHECK_U64(ranked[2]->fingerprint, 30);
        CHECK_U64(ranked[3]->fingerprint, 10);
        CHECK_U64(ranked[4]->fingerprint, 50);
        CHECK_U64(ranked[5]->fingerprint, 60);
    }
    free(ranked);
    cl_cluster_table_destroy(t);
}

static void test_growth(void)
{
    cl_cluster_table_t *t = cl_cluster_table_create();
    uint64_t fp;
    int ok = 1;

    /* Sequential keys stress the probe sequence; the finaliser must
     * still spread them out. */
    for (fp = 0; fp < 5000; fp++)
        ok &= cl_cluster_table_add(t, event("x", 1, "f", 0), fp) == 0;
    for (fp = 0; fp < 5000; fp += 2)
        ok &= cl_cluster_table_add(t, event("x", 1, "f", 0), fp) == 0;
    CHECK(ok);
    CHECK_INT(cl_cluster_table_size(t), 5000);
    CHECK_INT(cl_cluster_table_total(t), 7500);
    for (fp = 0; fp < 5000; fp++) {
        const cl_cluster_t *c = cl_cluster_table_find(t, fp);

        if (!c || c->count != (fp % 2 == 0 ? 2u : 1u)) {
            CHECK(!"cluster lost or miscounted after growth");
            break;
        }
    }
    cl_cluster_table_destroy(t);
}

const test_case_t cluster_tests[] = {
    { "counts_and_times", test_counts_and_times },
    { "representative_prefers_complete", test_representative_prefers_complete },
    { "ranking", test_ranking },
    { "growth", test_growth },
    { NULL, NULL },
};
