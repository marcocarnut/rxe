/*
 * rxejit runtime -- helpers the generated enumerator links in line.
 *
 * This is embedded into rxejit at build time (turned into a C string by a
 * Makefile rule) and written verbatim into every generated program that needs
 * it, so the emitted C stays self-contained: -S shows the whole mechanism, and
 * the compiled binary depends on nothing but the standard library. It is kept
 * here as ordinary C -- compilable, testable -- rather than as string literals
 * inside rxejit's codegen, which would be unmaintainable.
 *
 * What lives here is what the per-item sinks share. For match: FNV and a
 * read-only set of the target strings, built once before the threads run and
 * only read after, so no thread needs a lock to probe it. Dedup, when it lands,
 * extends the set with per-thread arenas and a merge.
 *
 *          (C) 2011 Marco "Kiko" Carnut <kiko at postcogito dot org>, GPLv2.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* FNV-1a, 64-bit, over n bytes. */
static unsigned long long rt_fnv(const unsigned char *s, unsigned long n)
{
    unsigned long long h = 1469598103934665603ULL;
    for (unsigned long i = 0; i < n; i++) { h ^= s[i]; h *= 1099511628211ULL; }
    return h;
}

/* A read-only set of byte strings -- the targets to match against. Open
 * addressing; the strings themselves live in 'store', the file read whole and
 * split in place. Built once, then only read, so probing is lock-free. */
struct rt_set {
    const char         **key;
    unsigned long       *len;
    unsigned long long  *hash;
    unsigned long        cap;      /* a power of two */
    char                *store;    /* the file's bytes, NUL-split */
};

static int rt_set_init(struct rt_set *s, unsigned long expect)
{
    unsigned long cap = 1024;
    while (cap * 7 <= expect * 10) cap *= 2;
    s->cap   = cap;
    s->store = NULL;
    s->key   = calloc(cap, sizeof *s->key);
    s->len   = calloc(cap, sizeof *s->len);
    s->hash  = calloc(cap, sizeof *s->hash);
    return s->key && s->len && s->hash;
}

static void rt_set_add(struct rt_set *s, const char *k, unsigned long n)
{
    unsigned long long h = rt_fnv((const unsigned char *)k, n);
    unsigned long i = (unsigned long)h & (s->cap - 1);
    while (s->key[i]) {
        if (s->hash[i] == h && s->len[i] == n && memcmp(s->key[i], k, n) == 0)
            return;                                    /* a repeated target */
        i = (i + 1) & (s->cap - 1);
    }
    s->key[i] = k; s->len[i] = n; s->hash[i] = h;
}

static int rt_set_has(const struct rt_set *s, const char *k, unsigned long n)
{
    unsigned long long h = rt_fnv((const unsigned char *)k, n);
    unsigned long i = (unsigned long)h & (s->cap - 1);
    while (s->key[i]) {
        if (s->hash[i] == h && s->len[i] == n && memcmp(s->key[i], k, n) == 0)
            return 1;
        i = (i + 1) & (s->cap - 1);
    }
    return 0;
}

/* Read a file, one target per line (a trailing CR/LF trimmed, blank lines
 * skipped), into the set. Returns 0 on success, -1 on any failure. */
static int rt_load(struct rt_set *s, const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return -1; }
    rewind(f);
    char *buf = malloc((unsigned long)sz + 1);
    if (!buf) { fclose(f); return -1; }
    unsigned long got = fread(buf, 1, (unsigned long)sz, f);
    fclose(f);
    buf[got] = 0;

    unsigned long lines = 1;
    for (unsigned long i = 0; i < got; i++) if (buf[i] == '\n') lines++;
    if (!rt_set_init(s, lines)) { free(buf); return -1; }
    s->store = buf;

    unsigned long start = 0;
    for (unsigned long i = 0; i <= got; i++) {
        if (i == got || buf[i] == '\n') {
            unsigned long e = i;
            while (e > start && buf[e - 1] == '\r') e--;
            if (e > start) rt_set_add(s, buf + start, e - start);
            start = i + 1;
        }
    }
    return 0;
}

static void rt_set_free(struct rt_set *s)
{
    free(s->key); free(s->len); free(s->hash); free(s->store);
}
