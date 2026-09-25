#ifndef CRASHLENS_CLUSTER_H
#define CRASHLENS_CLUSTER_H

#include <stddef.h>
#include <stdint.h>

#include "crashlens/crash_event.h"

#ifdef __cplusplus
extern "C" {
#endif

/* All crashes sharing one fingerprint. */
typedef struct {
    uint64_t          fingerprint;
    uint64_t          count;
    uint64_t          truncated;      /* members that were incomplete */
    int64_t           first_seen;     /* 0 when no member had a timestamp */
    int64_t           last_seen;
    size_t            sources;        /* distinct input files */
    /* The most complete member (most symbolised frames with locations);
     * ties keep the earliest one seen. */
    cl_crash_event_t *representative;
} cl_cluster_t;

typedef struct cl_cluster_table cl_cluster_table_t;

cl_cluster_table_t *cl_cluster_table_create(void);
void                cl_cluster_table_destroy(cl_cluster_table_t *t);

/* Adds one crash under the given fingerprint. Returns 0, or -1 when out
 * of memory (the table is left unchanged). */
int cl_cluster_table_add(cl_cluster_table_t *t, const cl_crash_event_t *ev,
                         uint64_t fingerprint);

size_t   cl_cluster_table_size(const cl_cluster_table_t *t);   /* clusters */
uint64_t cl_cluster_table_total(const cl_cluster_table_t *t);  /* crashes */

const cl_cluster_t *cl_cluster_table_find(const cl_cluster_table_t *t,
                                          uint64_t fingerprint);

/* Clusters ranked by count (descending), then most recent last_seen, then
 * fingerprint, so the order is fully deterministic. The returned array is
 * allocated with malloc and owned by the caller; its pointers stay valid
 * until the table is next modified. Returns NULL on allocation failure or
 * when the table is empty. */
const cl_cluster_t **cl_cluster_table_ranked(const cl_cluster_table_t *t,
                                             size_t *count);

#ifdef __cplusplus
}
#endif

#endif
