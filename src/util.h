#ifndef CRASHLENS_UTIL_H
#define CRASHLENS_UTIL_H

/* Internal string and number helpers. Everything here is written for
 * untrusted input: no locale dependence, explicit bounds, and overflow
 * checks on every numeric conversion. */

#include <stddef.h>
#include <stdint.h>

#define CL_ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))

static inline int cl_isdigit(int c)  { return c >= '0' && c <= '9'; }
static inline int cl_isspace(int c)  { return c == ' ' || c == '\t' || c == '\n' ||
                                              c == '\r' || c == '\v' || c == '\f'; }
static inline int cl_isxdigit(int c) { return cl_isdigit(c) || (c >= 'a' && c <= 'f') ||
                                              (c >= 'A' && c <= 'F'); }

/* Copies at most size-1 bytes and always NUL-terminates (when size > 0).
 * Returns strlen(src). */
size_t cl_strlcpy(char *dst, const char *src, size_t size);

/* Like cl_strlcpy but copies at most n bytes of src. */
void cl_strlcpyn(char *dst, const char *src, size_t n, size_t size);

char *cl_strdup(const char *s);

const char *cl_skip_space(const char *s);
int         cl_starts_with(const char *s, const char *prefix);

/* Trims trailing whitespace in place; returns the new length. */
size_t cl_rtrim(char *s);

/* Returns the substring [begin, end) with surrounding whitespace removed by
 * adjusting the two pointers. */
void cl_trim_range(const char **begin, const char **end);

/* Parses an unsigned integer in `base` (10 or 16) at *sp. A "0x" prefix is
 * accepted for base 16. On success advances *sp past the digits, stores the
 * value and returns 0; returns -1 on no digits or overflow. */
int cl_parse_u64(const char **sp, int base, uint64_t *out);

/* Parses "0x"-prefixed hex. */
int cl_parse_hex_addr(const char **sp, uint64_t *out);

/* Parses "YYYY-MM-DD[T ]HH:MM:SS[.fff][Z|+HH:MM|-HHMM]". Times without a
 * zone designator are taken as UTC. Returns 0 on success. */
int cl_parse_iso8601(const char *s, int64_t *out);

/* Formats as "YYYY-MM-DDTHH:MM:SSZ". */
void cl_format_iso8601(int64_t t, char *buf, size_t size);

/* Last path component, accepting both '/' and '\\' separators. */
const char *cl_basename(const char *path);

#endif
