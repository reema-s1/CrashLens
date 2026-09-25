#ifndef CRASHLENS_FS_H
#define CRASHLENS_FS_H

#include <stddef.h>

/* A growable list of file paths. */
typedef struct {
    char  **paths;
    size_t  count;
    size_t  capacity;
} cl_pathlist_t;

void cl_pathlist_free(cl_pathlist_t *list);

/* Takes ownership of `path` (a malloc'd string) on success. */
int cl_pathlist_push(cl_pathlist_t *list, char *path);

/* 1 if path is a directory, 0 if it is something else, -1 if it does not
 * exist or cannot be examined. */
int cl_fs_is_dir(const char *path);

/* Appends the regular files in `dir` (sorted by name; hidden entries
 * skipped), descending into subdirectories when `recursive` is set.
 * Returns 0, or -1 if the directory could not be read or memory ran out. */
int cl_fs_list_files(const char *dir, int recursive, cl_pathlist_t *out);

#endif
