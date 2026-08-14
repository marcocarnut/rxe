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

/* ---- a bump arena + a growing multiset, for the dedup sink ----------------
 * Each thread dedups its shard into its own rt_dup, so the hot loop shares
 * nothing and needs no lock; the sets are merged once, at the join. The members
 * are only ever added, never freed one at a time, so a stack of big blocks
 * handed out by the byte holds them: one malloc per block, the stack freed
 * together. */

#define RT_BLOCK (1u << 20)

struct rt_arena { char *cur, *end; char **block; unsigned long nblock, cblock; };

static char *rt_arena_dup(struct rt_arena *a, const char *s, unsigned long n)
{
    if ((unsigned long)(a->end - a->cur) < n) {
        unsigned long sz = n > RT_BLOCK ? n : RT_BLOCK;
        char *b = malloc(sz);
        if (!b) return NULL;
        if (a->nblock == a->cblock) {
            unsigned long nc = a->cblock ? a->cblock * 2 : 8;
            char **nb = realloc(a->block, nc * sizeof *nb);
            if (!nb) { free(b); return NULL; }
            a->block = nb; a->cblock = nc;
        }
        a->block[a->nblock++] = b;
        a->cur = b; a->end = b + sz;
    }
    char *p = a->cur;
    memcpy(p, s, n);
    a->cur += n;
    return p;
}

static void rt_arena_free(struct rt_arena *a)
{
    for (unsigned long i = 0; i < a->nblock; i++) free(a->block[i]);
    free(a->block);
}

struct rt_ent { char *key; unsigned long len; unsigned long long hash, mult; };

struct rt_dup {
    struct rt_ent      *slot;
    unsigned long       cap, used;   /* cap a power of two; used = distinct */
    unsigned long long  total;       /* members added, repeats and all */
    struct rt_arena     arena;
    int                 oom;
};

static int rt_dup_init(struct rt_dup *d)
{
    d->cap = 1024; d->used = 0; d->total = 0; d->oom = 0;
    d->arena = (struct rt_arena){ 0 };
    d->slot = calloc(d->cap, sizeof *d->slot);
    return d->slot != NULL;
}

static void rt_dup_place(struct rt_ent *slot, unsigned long cap, struct rt_ent e)
{
    unsigned long i = (unsigned long)e.hash & (cap - 1);
    while (slot[i].key) i = (i + 1) & (cap - 1);
    slot[i] = e;
}

static int rt_dup_grow(struct rt_dup *d)
{
    unsigned long ncap = d->cap * 2;
    struct rt_ent *ns = calloc(ncap, sizeof *ns);
    if (!ns) return 0;
    for (unsigned long i = 0; i < d->cap; i++)
        if (d->slot[i].key) rt_dup_place(ns, ncap, d->slot[i]);
    free(d->slot);
    d->slot = ns; d->cap = ncap;
    return 1;
}

/* Add a member: count it, and if its spelling is new store a copy, else bump the
 * one already there. */
static void rt_dup_add(struct rt_dup *d, const char *s, unsigned long n)
{
    d->total++;
    if (d->oom) return;
    if (d->used * 10 >= d->cap * 7 && !rt_dup_grow(d)) { d->oom = 1; return; }
    unsigned long long h = rt_fnv((const unsigned char *)s, n);
    unsigned long i = (unsigned long)h & (d->cap - 1);
    while (d->slot[i].key) {
        if (d->slot[i].hash == h && d->slot[i].len == n &&
            memcmp(d->slot[i].key, s, n) == 0) { d->slot[i].mult++; return; }
        i = (i + 1) & (d->cap - 1);
    }
    char *c = rt_arena_dup(&d->arena, s, n);
    if (!c) { d->oom = 1; return; }
    d->slot[i].key = c; d->slot[i].len = n; d->slot[i].hash = h; d->slot[i].mult = 1;
    d->used++;
}

/* Fold one thread's set into a master, summing multiplicity -- a member distinct
 * within a shard is still a duplicate if another shard rendered it. The bytes
 * are borrowed, not copied, so the source must outlive the merge. */
static void rt_dup_absorb(struct rt_dup *m, const struct rt_dup *o)
{
    m->total += o->total;
    if (o->oom) m->oom = 1;
    for (unsigned long i = 0; i < o->cap; i++) {
        if (!o->slot[i].key) continue;
        if (m->used * 10 >= m->cap * 7 && !rt_dup_grow(m)) { m->oom = 1; return; }
        struct rt_ent e = o->slot[i];
        unsigned long j = (unsigned long)e.hash & (m->cap - 1);
        while (m->slot[j].key) {
            if (m->slot[j].hash == e.hash && m->slot[j].len == e.len &&
                memcmp(m->slot[j].key, e.key, e.len) == 0) { m->slot[j].mult += e.mult; break; }
            j = (j + 1) & (m->cap - 1);
        }
        if (!m->slot[j].key) { m->slot[j] = e; m->used++; }
    }
}

static void rt_dup_free(struct rt_dup *d)
{
    rt_arena_free(&d->arena);
    free(d->slot);
}
