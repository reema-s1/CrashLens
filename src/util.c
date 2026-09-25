#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

size_t cl_strlcpy(char *dst, const char *src, size_t size)
{
    size_t len = strlen(src);

    if (size > 0) {
        size_t n = len < size - 1 ? len : size - 1;
        memcpy(dst, src, n);
        dst[n] = '\0';
    }
    return len;
}

void cl_strlcpyn(char *dst, const char *src, size_t n, size_t size)
{
    size_t i;

    if (size == 0)
        return;
    for (i = 0; i < n && i < size - 1 && src[i] != '\0'; i++)
        dst[i] = src[i];
    dst[i] = '\0';
}

char *cl_strdup(const char *s)
{
    size_t len = strlen(s) + 1;
    char *copy = malloc(len);

    if (copy)
        memcpy(copy, s, len);
    return copy;
}

const char *cl_skip_space(const char *s)
{
    while (cl_isspace((unsigned char)*s))
        s++;
    return s;
}

int cl_starts_with(const char *s, const char *prefix)
{
    return strncmp(s, prefix, strlen(prefix)) == 0;
}

size_t cl_rtrim(char *s)
{
    size_t len = strlen(s);

    while (len > 0 && cl_isspace((unsigned char)s[len - 1]))
        s[--len] = '\0';
    return len;
}

void cl_trim_range(const char **begin, const char **end)
{
    while (*begin < *end && cl_isspace((unsigned char)**begin))
        (*begin)++;
    while (*end > *begin && cl_isspace((unsigned char)(*end)[-1]))
        (*end)--;
}

static int digit_value(int c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return 99;
}

int cl_parse_u64(const char **sp, int base, uint64_t *out)
{
    const char *s = *sp;
    uint64_t value = 0;
    int ndigits = 0;
    int d;

    if (base == 16 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') &&
        cl_isxdigit((unsigned char)s[2]))
        s += 2;

    while ((d = digit_value((unsigned char)*s)) < base) {
        if (value > (UINT64_MAX - (uint64_t)d) / (uint64_t)base)
            return -1;
        value = value * (uint64_t)base + (uint64_t)d;
        s++;
        ndigits++;
    }
    if (ndigits == 0)
        return -1;
    *sp = s;
    *out = value;
    return 0;
}

int cl_parse_hex_addr(const char **sp, uint64_t *out)
{
    const char *s = *sp;

    if (s[0] != '0' || (s[1] != 'x' && s[1] != 'X'))
        return -1;
    return cl_parse_u64(sp, 16, out);
}

/* Days since 1970-01-01 for a proleptic Gregorian date. */
static int64_t days_from_civil(int64_t y, int m, int d)
{
    int64_t era, yoe, doy, doe;

    y -= m <= 2;
    era = (y >= 0 ? y : y - 399) / 400;
    yoe = y - era * 400;
    doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}

static void civil_from_days(int64_t z, int64_t *y, int *m, int *d)
{
    int64_t era, doe, yoe, doy, mp;

    z += 719468;
    era = (z >= 0 ? z : z - 146096) / 146097;
    doe = z - era * 146097;
    yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    mp = (5 * doy + 2) / 153;
    *d = (int)(doy - (153 * mp + 2) / 5 + 1);
    *m = (int)(mp < 10 ? mp + 3 : mp - 9);
    *y = yoe + era * 400 + (*m <= 2);
}

static int days_in_month(int64_t y, int m)
{
    static const int days[] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    int leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;

    return days[m - 1] + (m == 2 && leap);
}

/* Reads exactly `n` decimal digits. */
static int fixed_digits(const char **sp, int n, int *out)
{
    const char *s = *sp;
    int v = 0;
    int i;

    for (i = 0; i < n; i++) {
        if (!cl_isdigit((unsigned char)s[i]))
            return -1;
        v = v * 10 + (s[i] - '0');
    }
    *sp = s + n;
    *out = v;
    return 0;
}

int cl_parse_iso8601(const char *s, int64_t *out)
{
    int year, mon, day, hour, min, sec;
    int64_t t;

    if (fixed_digits(&s, 4, &year) || *s++ != '-' ||
        fixed_digits(&s, 2, &mon)  || *s++ != '-' ||
        fixed_digits(&s, 2, &day))
        return -1;
    if (*s != 'T' && *s != 't' && *s != ' ')
        return -1;
    s++;
    if (fixed_digits(&s, 2, &hour) || *s++ != ':' ||
        fixed_digits(&s, 2, &min)  || *s++ != ':' ||
        fixed_digits(&s, 2, &sec))
        return -1;

    if (mon < 1 || mon > 12 || day < 1 || day > days_in_month(year, mon) ||
        hour > 23 || min > 59 || sec > 60)
        return -1;

    if (*s == '.' || *s == ',') {
        s++;
        if (!cl_isdigit((unsigned char)*s))
            return -1;
        while (cl_isdigit((unsigned char)*s))
            s++;
    }

    t = days_from_civil(year, mon, day) * 86400 + hour * 3600 + min * 60 + sec;

    if (*s == 'Z' || *s == 'z') {
        s++;
    } else if (*s == '+' || *s == '-') {
        int sign = *s++ == '-' ? -1 : 1;
        int oh, om;

        if (fixed_digits(&s, 2, &oh))
            return -1;
        if (*s == ':')
            s++;
        if (fixed_digits(&s, 2, &om) || oh > 23 || om > 59)
            return -1;
        t -= sign * (oh * 3600 + om * 60);
    }

    s = cl_skip_space(s);
    if (*s != '\0')
        return -1;
    *out = t;
    return 0;
}

void cl_format_iso8601(int64_t t, char *buf, size_t size)
{
    int64_t days = t / 86400;
    int64_t secs = t % 86400;
    int64_t year;
    int mon, day;

    if (secs < 0) {
        secs += 86400;
        days--;
    }
    civil_from_days(days, &year, &mon, &day);
    snprintf(buf, size, "%04d-%02d-%02dT%02d:%02d:%02dZ", (int)year, mon, day,
             (int)(secs / 3600), (int)(secs / 60 % 60), (int)(secs % 60));
}

const char *cl_basename(const char *path)
{
    const char *base = path;
    const char *p;

    for (p = path; *p; p++)
        if (*p == '/' || *p == '\\')
            base = p + 1;
    return base;
}
