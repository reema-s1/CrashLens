#ifndef CRASHLENS_REPORT_H
#define CRASHLENS_REPORT_H

#include <stddef.h>
#include <stdio.h>

#include "crashlens/cluster.h"
#include "crashlens/fingerprint.h"
#include "crashlens/parser.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CRASHLENS_VERSION "0.1.0"

typedef struct {
    cl_fp_options_t          fp;            /* used to build the clusters */
    size_t                   max_clusters;  /* 0 = all */
    size_t                   max_frames;    /* frames per example; 0 = all */
    size_t                   inputs;        /* input files read */
    size_t                   unreadable;    /* input files that failed */
    const cl_parse_stats_t  *stats;         /* optional */
} cl_report_options_t;

void cl_report_options_default(cl_report_options_t *opts);

/* Ranked triage report. Both return 0, or -1 on allocation or write
 * failure. The JSON form is a single object, always valid UTF-8. */
int cl_report_text(FILE *out, const cl_cluster_table_t *t,
                   const cl_report_options_t *opts);
int cl_report_json(FILE *out, const cl_cluster_table_t *t,
                   const cl_report_options_t *opts);

#ifdef __cplusplus
}
#endif

#endif
