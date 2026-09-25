#define _POSIX_C_SOURCE 200809L

#include "fs.h"

#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <dirent.h>
#endif

#include "util.h"

#define MAX_DEPTH 64

typedef struct {
    char *name;
    int   is_dir;
} entry_t;

void cl_pathlist_free(cl_pathlist_t *list)
{
    size_t i;

    for (i = 0; i < list->count; i++)
        free(list->paths[i]);
    free(list->paths);
    list->paths = NULL;
    list->count = list->capacity = 0;
}

int cl_pathlist_push(cl_pathlist_t *list, char *path)
{
    if (list->count == list->capacity) {
        size_t cap = list->capacity ? list->capacity * 2 : 32;
        char **grown = realloc(list->paths, cap * sizeof(*grown));

        if (!grown)
            return -1;
        list->paths = grown;
        list->capacity = cap;
    }
    list->paths[list->count++] = path;
    return 0;
}

int cl_fs_is_dir(const char *path)
{
    struct stat st;

    if (stat(path, &st) != 0)
        return -1;
    return S_ISDIR(st.st_mode) ? 1 : 0;
}

static char *join(const char *dir, const char *name)
{
    size_t dlen = strlen(dir), nlen = strlen(name);
    int sep = dlen > 0 && dir[dlen - 1] != '/' && dir[dlen - 1] != '\\';
    char *path = malloc(dlen + (size_t)sep + nlen + 1);

    if (!path)
        return NULL;
    memcpy(path, dir, dlen);
    if (sep)
        path[dlen] = '/';
    memcpy(path + dlen + (size_t)sep, name, nlen + 1);
    return path;
}

static int entry_cmp(const void *a, const void *b)
{
    return strcmp(((const entry_t *)a)->name, ((const entry_t *)b)->name);
}

typedef struct {
    entry_t *items;
    size_t   count;
    size_t   capacity;
} entries_t;

static int entries_push(entries_t *e, const char *name, int is_dir)
{
    if (e->count == e->capacity) {
        size_t cap = e->capacity ? e->capacity * 2 : 32;
        entry_t *grown = realloc(e->items, cap * sizeof(*grown));

        if (!grown)
            return -1;
        e->items = grown;
        e->capacity = cap;
    }
    e->items[e->count].name = cl_strdup(name);
    if (!e->items[e->count].name)
        return -1;
    e->items[e->count].is_dir = is_dir;
    e->count++;
    return 0;
}

static void entries_free(entries_t *e)
{
    size_t i;

    for (i = 0; i < e->count; i++)
        free(e->items[i].name);
    free(e->items);
}

/* Reads one directory level. Symbolic links to directories are not
 * followed, which rules out cycles. */
static int read_dir(const char *dir, entries_t *out)
{
#ifdef _WIN32
    WIN32_FIND_DATAA fd;
    HANDLE h;
    char *pattern = join(dir, "*");
    int rc = 0;

    if (!pattern)
        return -1;
    h = FindFirstFileA(pattern, &fd);
    free(pattern);
    if (h == INVALID_HANDLE_VALUE)
        return -1;
    do {
        DWORD attr = fd.dwFileAttributes;

        if (fd.cFileName[0] == '.' || (attr & FILE_ATTRIBUTE_HIDDEN))
            continue;
        if ((attr & FILE_ATTRIBUTE_DIRECTORY) && (attr & FILE_ATTRIBUTE_REPARSE_POINT))
            continue;
        if (entries_push(out, fd.cFileName, (attr & FILE_ATTRIBUTE_DIRECTORY) != 0) != 0) {
            rc = -1;
            break;
        }
    } while (FindNextFileA(h, &fd));
    FindClose(h);
    return rc;
#else
    DIR *d = opendir(dir);
    struct dirent *de;
    int rc = 0;

    if (!d)
        return -1;
    while ((de = readdir(d)) != NULL) {
        struct stat st;
        char *path;
        int is_dir;

        if (de->d_name[0] == '.')
            continue;
        path = join(dir, de->d_name);
        if (!path) {
            rc = -1;
            break;
        }
        if (lstat(path, &st) != 0) {
            free(path);
            continue;
        }
        if (S_ISLNK(st.st_mode) && (stat(path, &st) != 0 || S_ISDIR(st.st_mode))) {
            free(path);
            continue;
        }
        free(path);
        if (!S_ISDIR(st.st_mode) && !S_ISREG(st.st_mode))
            continue;
        is_dir = S_ISDIR(st.st_mode);
        if (entries_push(out, de->d_name, is_dir) != 0) {
            rc = -1;
            break;
        }
    }
    closedir(d);
    return rc;
#endif
}

static int list_files(const char *dir, int recursive, int depth, cl_pathlist_t *out)
{
    entries_t entries = { NULL, 0, 0 };
    size_t i;
    int rc = read_dir(dir, &entries);

    if (rc == 0)
        qsort(entries.items, entries.count, sizeof(entries.items[0]), entry_cmp);

    for (i = 0; rc == 0 && i < entries.count; i++) {
        char *path;

        if (entries.items[i].is_dir && (!recursive || depth >= MAX_DEPTH))
            continue;
        path = join(dir, entries.items[i].name);
        if (!path) {
            rc = -1;
        } else if (entries.items[i].is_dir) {
            /* An unreadable subdirectory should not hide its siblings. */
            list_files(path, recursive, depth + 1, out);
            free(path);
        } else if (cl_pathlist_push(out, path) != 0) {
            free(path);
            rc = -1;
        }
    }
    entries_free(&entries);
    return rc;
}

int cl_fs_list_files(const char *dir, int recursive, cl_pathlist_t *out)
{
    return list_files(dir, recursive, 0, out);
}
