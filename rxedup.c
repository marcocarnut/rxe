/*
 * rxedup - brute-force duplicate detection over the set a regex describes.
 *          Where the structural certifier proves a set has no repeated
 *          spellings without looking at them, this walks the members and finds
 *          the repeats outright: it enumerates through rxe_foreach, hashes each
 *          rendered member into an exact set, and reports how many were seen
 *          more than once. It is the muscle behind the cheap proof -- the tier
 *          you reach for when the structure will not certify and the set is
 *          small enough to just look.
 *
 *          The answer is asymmetric, and the exit status says which way. A
 *          duplicate found is conclusive: the set has one, whether the walk was
 *          whole or capped. No duplicate found is conclusive only if the whole
 *          set was walked; over a capped or infinite set it means "none in the
 *          part we saw", nothing about the rest.
 *
 *          (C) 2011 Marco "Kiko" Carnut <kiko at postcogito dot org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * http://www.gnu.org/licenses/gpl-2.0.html for details.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <getopt.h>
#include "rxe.h"

#define MAXSTRLEN     2048          // default render width, as rxenum's
#define DEFAULT_CAP   1000000L      // members walked without an explicit -c

// Exit status, chosen so a script can branch on the three real answers:
//   0  every member walked was distinct, and the whole set was walked  -- a
//      brute-force certificate that the set holds no duplicate
//   1  a duplicate was found (conclusive however far the walk got)
//   2  no duplicate in the part walked, but the walk was capped or the set is
//      infinite -- inconclusive for the whole set
//   3  the regex would not parse, or a member was too big to render
enum { EX_DISTINCT = 0, EX_DUPLICATE = 1, EX_PARTIAL = 2, EX_ERROR = 3 };

/* ------------------------------- the exact set ------------------------------
 * Open-addressing table, one entry per distinct member. The stored bytes and
 * length make the comparison exact -- a member may hold a NUL, and two members
 * of different length are never equal -- while the cached hash makes a probe
 * that misses cheap. mult counts how many times the member was rendered, so -v
 * can name the repeats and their multiplicity.
 */

struct entry {
    char         *bytes;            // NULL in an empty slot
    size_t        len;
    uint64_t      hash;
    unsigned long mult;
};

// A bump allocator for the stored member bytes. Every distinct member used to
// cost a malloc; a run over a set with a million distinct members made a
// million of them, and the benchmark showed that -- not the pipe it saves --
// was where rxedup's time went. The members are only ever added, never freed
// one at a time, so a stack of big blocks handed out by the byte fits exactly:
// one allocation per block, and the whole stack freed at the end.
#define ARENA_BLOCK (1u << 20)

struct arena {
    char  *cur, *end;              // the free span of the current block
    char **block;                  // every block, to free them together
    size_t nblock, cblock;
};

static char *arena_dup(struct arena *a, const char *s, size_t len)
{
    if ((size_t)(a->end - a->cur) < len) {
        size_t sz = len > ARENA_BLOCK ? len : ARENA_BLOCK;  // outsize member gets its own
        char *b = malloc(sz);
        if (!b) return NULL;
        if (a->nblock == a->cblock) {
            size_t nc = a->cblock ? a->cblock * 2 : 8;
            char **nb = realloc(a->block, nc * sizeof *nb);
            if (!nb) { free(b); return NULL; }
            a->block = nb; a->cblock = nc;
        }
        a->block[a->nblock++] = b;
        a->cur = b; a->end = b + sz;
    }
    char *p = a->cur;
    memcpy(p, s, len);
    a->cur += len;
    return p;
}

static void arena_free(struct arena *a)
{
    for (size_t i = 0; i < a->nblock; i++) free(a->block[i]);
    free(a->block);
}

struct hset {
    struct entry *slot;
    size_t        cap;              // a power of two
    size_t        used;            // distinct members held
    int           oom;             // set once an allocation was refused
    struct arena  arena;           // the members' bytes live here
};

// A non-NULL, never-dereferenced key for the empty member, so its slot reads as
// occupied without the arena being asked for a zero-length span.
static char empty_key;

static uint64_t fnv1a(const char *s, size_t n)
{
    uint64_t h = 1469598103934665603ULL;    // FNV-1a, 64-bit
    for (size_t i = 0; i < n; i++) {
        h ^= (unsigned char)s[i];
        h *= 1099511628211ULL;
    }
    return h;
}

static int hset_init(struct hset *h)
{
    h->cap   = 1024;
    h->used  = 0;
    h->oom   = 0;
    h->arena = (struct arena){ 0 };
    h->slot  = calloc(h->cap, sizeof *h->slot);
    return h->slot != NULL;
}

// Place an entry that is known to be new -- used both by add() and by grow(),
// where every entry being moved is distinct by construction, so neither has to
// compare. The table never fills, so the empty-slot probe always terminates.
static void hset_place(struct entry *slot, size_t cap, struct entry e)
{
    size_t i = e.hash & (cap - 1);
    while (slot[i].bytes) i = (i + 1) & (cap - 1);
    slot[i] = e;
}

static int hset_grow(struct hset *h)
{
    size_t ncap = h->cap * 2;
    struct entry *ns = calloc(ncap, sizeof *ns);
    if (!ns) { h->oom = 1; return 0; }
    for (size_t i = 0; i < h->cap; i++)
        if (h->slot[i].bytes) hset_place(ns, ncap, h->slot[i]);
    free(h->slot);
    h->slot = ns;
    h->cap  = ncap;
    return 1;
}

// Add one member. Returns 1 if it was new, 0 if it had been seen before (a
// duplicate) or if memory ran out -- the caller reads h->oom to tell those two
// apart, since neither adds to the distinct count.
static int hset_add(struct hset *h, const char *s, size_t len)
{
    if (h->used * 10 >= h->cap * 7 && !hset_grow(h)) return 0;
    uint64_t hash = fnv1a(s, len);
    size_t i = hash & (h->cap - 1);
    while (h->slot[i].bytes) {
        struct entry *e = &h->slot[i];
        if (e->hash == hash && e->len == len && memcmp(e->bytes, s, len) == 0) {
            e->mult++;
            return 0;               // a repeat
        }
        i = (i + 1) & (h->cap - 1);
    }
    char *copy = len ? arena_dup(&h->arena, s, len) : &empty_key;
    if (!copy) { h->oom = 1; return 0; }
    h->slot[i].bytes = copy;
    h->slot[i].len   = len;
    h->slot[i].hash  = hash;
    h->slot[i].mult  = 1;
    h->used++;
    return 1;
}

static void hset_free(struct hset *h)
{
    arena_free(&h->arena);
    free(h->slot);
}

/* ------------------------------- the walk ---------------------------------- */

struct run {
    struct hset   set;
    unsigned long total;           // members walked
};

static int dup_sink(const char *s, size_t len, const mpz_t index, void *v)
{
    struct run *r = v;
    (void)index;
    r->total++;
    hset_add(&r->set, s, len);
    if (r->set.oom) return 1;       // stop cleanly; the caller reports it
    return 0;
}

/* ------------------------------ dictionaries ------------------------------- */
/* The same [:name:] word lists rxenum reads: a "name.dict" file, one word per
 * line, looked up in the -D directories then the current one. Resolution runs
 * at parse time, before any walk, so the registered words are only ever read
 * after -- which matters once the walk is threaded. Lifted from rxenum. */

#define MAX_DICT_DIRS 16
static const char *dict_dirs[MAX_DICT_DIRS];
static int         ndict_dirs;

static char **load_dict_file(const char *path, int *nwords)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) return NULL;
    int cap = 64, n = 0;
    char **words = malloc(cap * sizeof(char *));
    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        int len = strlen(line);
        while (len && (line[len-1] == '\n' || line[len-1] == '\r')) line[--len] = 0;
        if (n == cap) { cap *= 2; words = realloc(words, cap * sizeof(char *)); }
        words[n] = malloc(len + 1);
        memcpy(words[n], line, len + 1);
        n++;
    }
    fclose(fp);
    *nwords = n;
    return words;
}

// Registers the words with the library, which keeps its own copy, so the
// loaded ones are freed straight away. Returns 1 if a file was found.
static int dict_resolver(const char *name)
{
    for (int d = -1; d < ndict_dirs; d++) {
        char path[1024];
        const char *dir = d < 0 ? "." : dict_dirs[d];
        snprintf(path, sizeof(path), "%s/%s.dict", dir, name);
        int nwords;
        char **words = load_dict_file(path, &nwords);
        if (!words) continue;
        rxe_register_dict(name, (const char **)words, nwords);
        for (int i = 0; i < nwords; i++) free(words[i]);
        free(words);
        return 1;
    }
    return 0;
}

/* ------------------------------- the program ------------------------------- */

static const char *prog = "rxedup";

static void usage(FILE *out)
{
    fprintf(out,
"usage: %s [-c count] [-w width] [-v] [-q] REGEX\n"
"\n"
"Walk the members of the set REGEX describes and report duplicate renderings.\n"
"\n"
"  -c count  walk at most 'count' members (0 = no cap); default %ld. A finite\n"
"            set smaller than the cap is walked whole; an infinite one, or a\n"
"            larger finite one, is walked only that far and the answer is then\n"
"            inconclusive unless a duplicate turns up.\n"
"  -w width  render buffer in bytes (default %d); a longer member is refused.\n"
"  -D dir    also look in 'dir' for a [:name:] dictionary's name.dict file.\n"
"  -v        after the summary, list the repeated members and their counts.\n"
"  -q        print nothing; report only through the exit status.\n"
"\n"
"exit: 0 all distinct (whole set walked), 1 a duplicate found,\n"
"      2 none found but the walk was capped or infinite, 3 error.\n",
        prog, DEFAULT_CAP, MAXSTRLEN);
}

static void list_repeats(const struct hset *h)
{
    for (size_t i = 0; i < h->cap; i++) {
        const struct entry *e = &h->slot[i];
        if (e->bytes && e->mult > 1)
            printf("  %lu× %.*s\n", e->mult, (int)e->len, e->bytes);
    }
}

int main(int argc, char **argv)
{
    long   cap     = DEFAULT_CAP;
    int    width   = MAXSTRLEN;
    int    verbose = 0, quiet = 0;
    int    opt;

    if (argc > 0) prog = argv[0];
    while ((opt = getopt(argc, argv, "c:w:D:vqh")) != -1) {
        switch (opt) {
            case 'c': cap = strtol(optarg, NULL, 10);
                      if (cap < 0) { fprintf(stderr, "%s: -c needs a count >= 0\n", prog); return EX_ERROR; }
                      break;
            case 'w': width = atoi(optarg);
                      if (width < 1) { fprintf(stderr, "%s: -w needs a positive width\n", prog); return EX_ERROR; }
                      break;
            case 'D': if (ndict_dirs < MAX_DICT_DIRS) dict_dirs[ndict_dirs++] = optarg; break;
            case 'v': verbose = 1; break;
            case 'q': quiet = 1; break;
            case 'h': usage(stdout); return EX_DISTINCT;
            default:  usage(stderr); return EX_ERROR;
        }
    }
    if (optind != argc - 1) { usage(stderr); return EX_ERROR; }
    const char *pattern = argv[optind];

    rxe_init();
    rxe_set_dict_resolver(dict_resolver);
    atexit(rxe_free_dicts);
    struct rxe *rxe = rxe_parse(pattern, 0);
    if (rxe_error(rxe) != RXE_OK) {
        if (!quiet)
            fprintf(stderr, "%s: %s\n", prog, rxe_error_message(rxe));
        rxe_free(rxe);
        return EX_ERROR;
    }

    int infinite = rxe_is_infinite(rxe);

    // How far to walk. A count of zero into rxe_foreach means "no limit", which
    // is what an uncapped run of a finite set wants; a positive cap bounds an
    // infinite or oversized set. The default cap still applies when -c is
    // absent, so a stray huge set does not thrash unbidden.
    mpz_t from, count;
    mpz_init_set_ui(from, 0);
    mpz_init(count);
    if (cap == 0) mpz_set_ui(count, 0);            // uncapped, on request
    else          mpz_set_si(count, cap);

    struct run r;
    r.total = 0;
    if (!hset_init(&r.set)) {
        if (!quiet) fprintf(stderr, "%s: out of memory\n", prog);
        mpz_clear(from); mpz_clear(count); rxe_free(rxe);
        return EX_ERROR;
    }

    int fr = rxe_foreach(rxe, from, count, width, dup_sink, &r);

    unsigned long total    = r.total;
    unsigned long distinct = (unsigned long)r.set.used;
    unsigned long dups     = total - distinct;

    // Whether the whole set was seen. A finite set is whole when the walk ran
    // to its end rather than stopping on the count; rxe_foreach reports END for
    // both, so compare against the known size. An infinite set is never whole.
    int whole = 0;
    if (!infinite) {
        // total == nitems exactly when nothing was left unwalked.
        mpz_t n;
        mpz_init_set(n, rxe->nitems);
        whole = (mpz_cmp_ui(n, total) == 0);
        mpz_clear(n);
    }

    int status;
    if (fr == RXE_FOREACH_TOOBIG || (r.set.oom && dups == 0 && !whole && total == 0)) {
        // A render overflow, or memory gone before a single member landed.
        if (!quiet)
            fprintf(stderr, "%s: %s\n", prog,
                fr == RXE_FOREACH_TOOBIG
                    ? "a member is larger than the render width; raise -w"
                    : "out of memory");
        status = EX_ERROR;
    } else if (dups > 0) {
        if (!quiet)
            printf("%lu member%s, %lu distinct, %lu duplicate%s -- NOT distinct\n",
                   total, total == 1 ? "" : "s", distinct,
                   dups, dups == 1 ? "" : "s");
        if (verbose && !quiet) list_repeats(&r.set);
        status = EX_DUPLICATE;
    } else if (r.set.oom) {
        if (!quiet)
            printf("%lu members, all distinct so far, then out of memory "
                   "-- inconclusive\n", total);
        status = EX_PARTIAL;
    } else if (whole) {
        if (!quiet)
            printf("%lu member%s, all distinct\n", total, total == 1 ? "" : "s");
        status = EX_DISTINCT;
    } else {
        if (!quiet)
            printf("%lu member%s walked, all distinct -- inconclusive "
                   "(%s)\n", total, total == 1 ? "" : "s",
                   infinite ? "the set is infinite" : "the walk was capped");
        status = EX_PARTIAL;
    }

    hset_free(&r.set);
    mpz_clear(from);
    mpz_clear(count);
    rxe_free(rxe);
    return status;
}
