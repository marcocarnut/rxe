/*
 * rxejit - compile a regex-set into C that enumerates it.
 *
 *          rxenum walks the set through the library's interpreter: a tree of
 *          nodes, an mpz index, a function call per member. For a bruteforce --
 *          keycracking, dedup, fuzzing -- that interpreter is the whole cost,
 *          and the benchmark said so. This emits C specialised to one regex
 *          instead: an unrolled odometer over fixed char buffers, incremented
 *          by carry, that the system compiler then optimises. No tree, no mpz,
 *          no indirect call.
 *
 *          Each position of a member is a "wheel": a character class, or an
 *          alternation or bounded repeat baked out by the interpreter. When a
 *          wheel's branches are all one length the member sits at compile-time
 *          offsets, delta-patched as the odometer turns; when they vary
 *          ([a-z]{1,3}, (cat|hi)) the member is rebuilt each step. A
 *          backreference is no wheel at all -- it copies the bytes of the group
 *          it names, tracked in local variables the generated code sets as the
 *          group is laid. A variable-count repeat too large to bake into one
 *          wheel ([a-z]{1,7} is 8 billion) becomes a super-wheel of the odometer
 *          instead: a base-(the body) number whose length grows from a to b. So
 *          masks, alternations even and uneven, subroutines, bounded repeats big
 *          and small, dictionaries, and backreferences all compile -- every
 *          finite pattern. Only an unbounded (infinite) repeat, or an
 *          alternation/dictionary too large to unroll, declines by name, and the
 *          interpreter stays the answer there. It runs the compiled program (or
 *          prints the C with -S) under a chosen sink: write the members, count
 *          them, match them
 *          against a target set (MD5 too, for keycracking), or find duplicates.
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
#include <unistd.h>
#include <sys/wait.h>
#include "rxe.h"
#include "rxejit_rt_embed.h"       // RXEJIT_RT: the runtime, as a C string
#include "rxejit_cl_embed.h"       // RXEJIT_CL: the device runtime for -G

#define MAXW 4096                  // most positions an unrolled mask may have

// What the generated loop does with each member. write is the default -- the
// members to stdout, as rxenum -e does; count only tallies them, which times
// the enumeration with no I/O in the way; match probes each against a target
// set loaded at runtime and prints the hits (a mask being a keyspace to sift);
// dup hashes each into a per-thread set and reports the repeats, merged at the
// join -- meaningful now that alternations put duplicates in the set.
enum { SINK_WRITE, SINK_COUNT, SINK_MATCH, SINK_DUP };

#define ALT_CAP 65536              // most members a baked alternation may hold
#define REP_SUBW 64                // most fixed sub-wheels a loop repeat's body may hold

// One odometer wheel: n alternatives at 'base'. When every alternative is the
// same length it is fixed -- L bytes, alternative i at base + i*L, the fast
// case (a class is L==1). When they differ it is variable -- L is 0, and aoff[i]
// / alen[i] give alternative i's start and length in 'base'. A member's fixed
// wheels sit at compile-time offsets; a variable one makes the offsets of every
// wheel after it depend on the choice, so such members are rebuilt each step.
struct wheel { const char *base; int n; int L; const int *aoff; const int *alen; };

static const char *reason;         // why a pattern was declined, for the message

// The render is a sequence of ops, in member order. Usually just LAY the wheels;
// a backreference adds a COPY of an earlier group's bytes, bracketed by the
// OPEN/CLOSE that record where that group landed. Only these interleave the
// wheel-laying, so a pattern without backrefs is a plain run of LAYs.
enum { OP_LAY, OP_OPEN, OP_CLOSE, OP_COPY };
struct op { int kind; int arg; };   // arg = wheel index (LAY) or group id (rest)

// The running build: the wheels gathered so far, the render ops, the groups a
// backreference names (matched by their rxe pointer), and every buffer baked
// for an alternation -- all freed once the code is out.
struct build {
    struct wheel *w;
    int           nw;
    struct op    *ops;
    int           nops, cops;
    struct rxe  **gref;           // rxe pointers a backreference targets (pass 1)
    int           ngref;
    struct rxe  **grxe;           // groups opened so far, and their ids by index
    int           ngroup;
    int           has_backref;
    void        **bake;
    int           nbake, cbake;
    struct rxe   *root;            // the whole pattern, for a node's source span

    // A variable-count repeat X{a,b} too large to unroll: kept as a super-wheel
    // rather than baked into one giant wheel. pre = w[0..lr_at), post = the
    // wheels appended after; the body X is lr_nsw fixed sub-wheels laid lr_a..
    // lr_b times -- an odometer whose length grows, a base-(product of the
    // sub-wheels) number. Only one such repeat, and only fixed sub-wheels.
    int           lr_active, lr_at, lr_a, lr_b, lr_nsw;
    struct wheel  lr_sw[REP_SUBW];
};

static int emit_op(struct build *b, int kind, int arg)
{
    if (b->nops == b->cops) {
        int nc = b->cops ? b->cops * 2 : 16;
        struct op *no = realloc(b->ops, (size_t)nc * sizeof *no);
        if (!no) { reason = "out of memory"; return -1; }
        b->ops = no; b->cops = nc;
    }
    b->ops[b->nops].kind = kind; b->ops[b->nops].arg = arg;
    b->nops++;
    return 0;
}

// A group's id is its slot in grxe, assigned the first time it is opened. Search
// only; the backref uses this so a forward reference (group not yet opened)
// returns -1 and is declined.
static int group_of(struct build *b, struct rxe *rxe)
{
    for (int i = 0; i < b->ngroup; i++) if (b->grxe[i] == rxe) return i;
    return -1;
}

// Whether a backreference names this group, and if so its id, assigning one on
// first open. Groups nothing points at stay untracked (id -1, no OPEN/CLOSE).
static int group_open_id(struct build *b, struct rxe *rxe)
{
    int referenced = 0;
    for (int i = 0; i < b->ngref; i++) if (b->gref[i] == rxe) { referenced = 1; break; }
    if (!referenced) return -1;
    int g = group_of(b, rxe);
    if (g >= 0) return g;                       // reopened (a repeated group)
    b->grxe = realloc(b->grxe, (size_t)(b->ngroup + 1) * sizeof *b->grxe);
    if (!b->grxe) { reason = "out of memory"; return -2; }
    b->grxe[b->ngroup] = rxe;
    return b->ngroup++;
}

static int keep(struct build *b, void *p)   // track an allocation for freeing
{
    if (!p) { reason = "out of memory"; return -1; }
    if (b->nbake == b->cbake) {
        int nc = b->cbake ? b->cbake * 2 : 8;
        void **nb = realloc(b->bake, (size_t)nc * sizeof *nb);
        if (!nb) { reason = "out of memory"; return -1; }
        b->bake = nb; b->cbake = nc;
    }
    b->bake[b->nbake++] = p;
    return 0;
}

static int add_wheel(struct build *b, const char *base, int n, int L,
                     const int *aoff, const int *alen)
{
    if (n < 1)         { reason = "an empty class"; return -1; }
    if (b->nw >= MAXW) { reason = "too many positions to unroll"; return -1; }
    if (emit_op(b, OP_LAY, b->nw)) return -1;
    b->w[b->nw] = (struct wheel){ base, n, L, aoff, alen };
    b->nw++;
    return 0;
}

static int add_rxe(struct build *b, struct rxe *rxe);

// An alternation becomes one wheel by baking its members: enumerate them with
// the interpreter, in seek order -- the very order the parent odometer drives
// this position through -- and store them as the wheel's alternatives. Equal
// lengths give a fixed wheel, uneven ones a variable wheel. Duplicate branches
// like (a|a) bake to repeated alternatives, so the odometer visits the repeat
// and a dedup sink can see it -- which is the point of taking alternations.
static int bake_alt(struct build *b, struct rxe *rxe)
{
    if (rxe->ninf || !mpz_fits_ulong_p(rxe->nitems)) {
        reason = "too many members to unroll"; return -1;
    }
    unsigned long n = mpz_get_ui(rxe->nitems);
    if (n < 1)       { reason = "an empty alternation"; return -1; }
    if (n > ALT_CAP) { reason = "too many members to unroll"; return -1; }

    int *aoff = malloc(n * sizeof *aoff);
    int *alen = malloc(n * sizeof *alen);
    char *buf = NULL;
    unsigned long cap = 0, total = 0;
    char tmp[4096];
    mpz_t idx;
    mpz_init(idx);
    if (!aoff || !alen) { reason = "out of memory"; goto fail; }

    for (unsigned long i = 0; i < n; i++) {
        mpz_set_ui(idx, i);
        if (rxe_seek(rxe, idx)) { reason = "an alternation that would not seek"; goto fail; }
        char *end = rxe_current(tmp, (int)sizeof tmp - 1, rxe);
        int len = (int)(end - tmp);
        if (len >= (int)sizeof tmp - 1) { reason = "an alternation member too long"; goto fail; }
        if (total + (unsigned long)len > cap) {
            cap = (total + (unsigned long)len) * 2 + 16;
            char *nb = realloc(buf, cap);
            if (!nb) { reason = "out of memory"; goto fail; }
            buf = nb;
        }
        memcpy(buf + total, tmp, (size_t)len);
        aoff[i] = (int)total; alen[i] = len; total += (unsigned long)len;
    }
    mpz_clear(idx);
    if (!buf) { buf = malloc(1); if (!buf) { reason = "out of memory"; free(aoff); free(alen); return -1; } }

    int fixed = 1;
    for (unsigned long i = 1; i < n; i++) if (alen[i] != alen[0]) { fixed = 0; break; }

    if (keep(b, buf)) { free(buf); free(aoff); free(alen); return -1; }
    if (fixed) {
        int L0 = alen[0];
        free(aoff); free(alen);
        return add_wheel(b, buf, (int)n, L0, NULL, NULL);
    }
    if (keep(b, aoff) || keep(b, alen)) { free(aoff); free(alen); return -1; }
    return add_wheel(b, buf, (int)n, 0, aoff, alen);
fail:
    free(buf); free(aoff); free(alen);
    mpz_clear(idx);
    return -1;
}

// A dictionary is a wheel whose alternatives are its words -- built straight
// from the word list rather than enumerated, but otherwise an uneven-length
// alternation like any other. So [:bip39en:]{4} is four such wheels.
static int bake_dict(struct build *b, struct rxe_node *nd)
{
    int n = nd->nwords;
    if (n < 1)       { reason = "an empty dictionary"; return -1; }
    if (n > ALT_CAP) { reason = "too many members to unroll"; return -1; }

    int *aoff = malloc((size_t)n * sizeof *aoff);
    int *alen = malloc((size_t)n * sizeof *alen);
    if (!aoff || !alen) { free(aoff); free(alen); reason = "out of memory"; return -1; }

    unsigned long total = 0;
    for (int i = 0; i < n; i++) {
        int L = (int)strlen(nd->words[i]);
        aoff[i] = (int)total; alen[i] = L; total += (unsigned long)L;
    }
    char *buf = malloc(total ? total : 1);
    if (!buf) { free(aoff); free(alen); reason = "out of memory"; return -1; }
    for (int i = 0; i < n; i++) memcpy(buf + aoff[i], nd->words[i], (size_t)alen[i]);

    int fixed = 1;
    for (int i = 1; i < n; i++) if (alen[i] != alen[0]) { fixed = 0; break; }

    if (keep(b, buf)) { free(buf); free(aoff); free(alen); return -1; }
    if (fixed) {
        int L0 = alen[0];
        free(aoff); free(alen);
        return add_wheel(b, buf, n, L0, NULL, NULL);
    }
    if (keep(b, aoff) || keep(b, alen)) { free(aoff); free(alen); return -1; }
    return add_wheel(b, buf, n, 0, aoff, alen);
}

// A variable-count repeat X{a,b} too large to unroll (bake would blow past
// ALT_CAP): keep it as a super-wheel instead. Collect X's own wheels -- one copy
// of the body, in nd->rxe -- then lift them out of the main stream into lr_sw,
// where they are the body positions laid a..b times, not pre/post wheels. They
// must all be fixed width (a variable-width body would alias lengths across the
// odometer, which this path does not yet render), and hold no group a
// backreference could name. Only one such repeat per pattern.
static int add_looprep(struct build *b, struct rxe_node *nd)
{
    if (b->lr_active) { reason = "more than one large variable-count repeat"; return -1; }
    if (b->ngref)     { reason = "a large variable-count repeat with a backreference"; return -1; }
    int w0 = b->nw, op0 = b->nops, g0 = b->ngroup;
    if (add_rxe(b, nd->rxe)) return -1;
    if (b->ngroup != g0) { reason = "a group inside a large variable-count repeat"; return -1; }
    int m = b->nw - w0;
    if (m < 1)         { reason = "an empty large variable-count repeat"; return -1; }
    if (m > REP_SUBW)  { reason = "too many positions in a variable-count repeat body"; return -1; }
    for (int i = 0; i < m; i++)
        if (b->w[w0 + i].L == 0) { reason = "a variable-width body in a large variable-count repeat"; return -1; }
    for (int i = 0; i < m; i++) b->lr_sw[i] = b->w[w0 + i];
    b->lr_nsw   = m;
    b->lr_a     = nd->rep_min;
    b->lr_b     = nd->rep_max;
    b->lr_at    = w0;             // pre = w[0..w0); post wheels get appended here
    b->lr_active = 1;
    b->nw       = w0;            // drop the body wheels from the main stream,
    b->nops     = op0;          // and the LAY ops that went with them
    return 0;
}

// One node -> wheel(s): a plain class is one L==1 wheel; an exact {k} repeat is
// its body's wheels laid down k times; a group recurses into its subexpression.
static int add_node(struct build *b, struct rxe_node *nd)
{
    int plain = !nd->is_repeat && !nd->is_comb && !nd->is_shuffle &&
                !nd->is_dict && !nd->is_backref && !nd->is_inf && !nd->rxe;
    if (plain)
        return add_wheel(b, nd->str, nd->len, 1, NULL, NULL);

    // A backreference is no wheel: it copies the bytes of the group it names,
    // which must already be open (a backward reference). Its rxe pointer is the
    // group's, so group_of finds the id.
    if (nd->is_backref) {
        b->has_backref = 1;
        int g = group_of(b, nd->rxe);
        if (g < 0) { reason = "a forward or unresolved backreference"; return -1; }
        return emit_op(b, OP_COPY, g);
    }

    if (nd->is_dict)
        return bake_dict(b, nd);

    if (nd->is_repeat && !nd->is_inf && nd->rep_max != RXE_REP_UNBOUNDED &&
        nd->rep_min == nd->rep_max && nd->rxe) {
        for (int k = 0; k < nd->rep_min; k++)
            if (add_rxe(b, nd->rxe)) return -1;
        return 0;
    }

    // A bounded variable repeat X{a,b} is finite and place-value ordered (only
    // an unbounded one is shortlex), but its members vary in width. When few
    // enough, re-parse its own source span and bake it as one variable wheel --
    // the same treatment an uneven alternation gets, and the tested path for a
    // modest repeat. When the unroll would be too big ([a-z]{1,7} is 8 billion),
    // keep it as a loop super-wheel instead, growing an odometer from a to b.
    if (nd->is_repeat && !nd->is_inf && nd->rep_max != RXE_REP_UNBOUNDED && nd->rxe) {
        int len = nd->src_end - nd->src_start;
        if (len > 0 && b->root->source) {
            char *sub = malloc((size_t)len + 1);
            if (!sub) { reason = "out of memory"; return -1; }
            memcpy(sub, b->root->source + nd->src_start, (size_t)len);
            sub[len] = 0;
            struct rxe *sr = rxe_parse(sub, 0);
            free(sub);
            if (rxe_error(sr) == RXE_OK && !sr->ninf && mpz_fits_ulong_p(sr->nitems)
                && mpz_get_ui(sr->nitems) <= ALT_CAP) {
                int rc = bake_alt(b, sr);
                rxe_free(sr);
                return rc;
            }
            rxe_free(sr);
        }
        return add_looprep(b, nd);
    }

    if (nd->rxe && !nd->is_repeat && !nd->is_comb && !nd->is_shuffle &&
        !nd->is_dict && !nd->is_backref && !nd->is_inf)
        return add_rxe(b, nd->rxe);

    reason = nd->is_inf     ? "an unbounded repeat"
           : nd->is_dict    ? "a dictionary"
           : nd->is_backref ? "a backreference"
           : nd->is_comb    ? "a combination"
           : nd->is_shuffle ? "a shuffle"
           : nd->is_repeat  ? "a variable-count repeat"
           :                  "an unsupported element";
    return -1;
}

// An expression -> wheels: an alternation (more than one branch) bakes to one
// wheel; a single branch is its nodes in order.
static int add_rxe(struct build *b, struct rxe *rxe)
{
    if (rxe->flags & (RXE_FLAG_LEFT_TO_RIGHT | RXE_FLAG_SHORTLEX)) {
        reason = "a non-default enumeration order"; return -1;
    }
    if (!rxe->head) { reason = "an empty expression"; return -1; }

    // If a backreference names this group, bracket its bytes so a later copy can
    // find them. A group opened more than once (a repeated group) records each
    // time, so the copy sees the last -- which is rxe's binding.
    int g = group_open_id(b, rxe);
    if (g == -2) return -1;
    if (g >= 0 && emit_op(b, OP_OPEN, g)) return -1;

    int rc = 0;
    if (rxe->head->next)
        rc = bake_alt(b, rxe);
    else
        for (struct rxe_node *nd = rxe->head->head; nd; nd = nd->next)
            if (add_node(b, nd)) { rc = -1; break; }

    if (rc == 0 && g >= 0 && emit_op(b, OP_CLOSE, g)) return -1;
    return rc;
}

// Pass 1: collect the rxe pointers a backreference names, so pass 2 knows which
// groups to bracket. A backref's own rxe is the target; other nodes recurse.
static int find_refs(struct build *b, struct rxe *rxe)
{
    for (struct rxe_alt *a = rxe->head; a; a = a->next)
        for (struct rxe_node *n = a->head; n; n = n->next) {
            if (n->is_backref) {
                int have = 0;
                for (int i = 0; i < b->ngref; i++) if (b->gref[i] == n->rxe) { have = 1; break; }
                if (!have) {
                    struct rxe **ng = realloc(b->gref, (size_t)(b->ngref + 1) * sizeof *ng);
                    if (!ng) { reason = "out of memory"; return -1; }
                    b->gref = ng; b->gref[b->ngref++] = n->rxe;
                }
            } else if (n->rxe) {
                if (find_refs(b, n->rxe)) return -1;
            }
        }
    return 0;
}

// Gather the wheels for the whole pattern. Returns the count, or -1 with
// 'reason' set. On success the caller must free the buffers (free_build).
static int collect(struct build *b, struct rxe *rxe)
{
    b->nw = 0; b->bake = NULL; b->nbake = 0; b->cbake = 0; b->root = rxe;
    b->ops = NULL; b->nops = 0; b->cops = 0;
    b->gref = NULL; b->ngref = 0; b->grxe = NULL; b->ngroup = 0; b->has_backref = 0;
    b->lr_active = 0;
    if (find_refs(b, rxe)) return -1;
    if (add_rxe(b, rxe)) return -1;
    // A loop super-wheel renders a variable-length tail, so every pre/post wheel
    // around it must be fixed and no backreference may reach across it -- the
    // things this path does not yet interleave. (A single big repeat with all
    // else fixed, the common keyspace, is what it takes.)
    if (b->lr_active) {
        if (b->has_backref) { reason = "a backreference alongside a large variable-count repeat"; return -1; }
        for (int i = 0; i < b->nw; i++)
            if (b->w[i].L == 0) { reason = "a variable-width position alongside a large variable-count repeat"; return -1; }
    }
    return b->nw;
}

static void free_build(struct build *b)
{
    for (int i = 0; i < b->nbake; i++) free(b->bake[i]);
    free(b->bake); free(b->ops); free(b->gref); free(b->grxe);
}

// Print the pattern into a C comment, defusing any */ that would close it.
static void emit_comment(FILE *o, const char *s)
{
    for (; *s; s++) fputc((*s == '*' && s[1] == '/') ? ' ' : *s, o);
}

// Emit the statement that lays wheel i's alternative 'idx' into the buffer at
// 'off': a single byte for a class, a memcpy for a wider alternation branch.
static void emit_lay(FILE *o, int i, int off, int L, const char *idx)
{
    if (L == 1) fprintf(o, "buf[%d] = A%d[%s];", off, i, idx);
    else        fprintf(o, "memcpy(buf + %d, A%d + (%s) * %d, %d);", off, i, idx, L, L);
}

#define DUP_LIST_CAP 10000000L     // most members -d -v will enumerate to list

// How many of a wheel's n alternatives are distinct. Each wheel writes a fixed,
// disjoint slice of the member, so the whole set's distinct count is the product
// of these -- a closed form for dedup, no enumeration, however large the set.
static int g_cmpL;
static int cmp_alt(const void *a, const void *b)
{
    return memcmp(*(const char *const *)a, *(const char *const *)b, (size_t)g_cmpL);
}
static int wheel_distinct(const struct wheel *w)
{
    if (w->n <= 1) return w->n;
    const char **p = malloc((size_t)w->n * sizeof *p);
    if (!p) return w->n;                       // can't check; assume distinct
    for (int i = 0; i < w->n; i++) p[i] = w->base + (size_t)i * w->L;
    g_cmpL = w->L;
    qsort(p, w->n, sizeof *p, cmp_alt);
    int d = 1;
    for (int i = 1; i < w->n; i++) if (memcmp(p[i], p[i-1], (size_t)w->L)) d++;
    free(p);
    return d;
}

// The per-member sink action, using 'len' as the member length expression (a
// constant when fixed, "p" when variable) and 'lenp1' as length+1 for a write.
static void emit_sink(FILE *o, int dup, int match, int count, int hash,
                      const char *len, const char *lenp1)
{
    if (dup)        fprintf(o, "        rt_dup_add(d, (const char *)buf, %s);\n", len);
    else if (match && hash)
                    fprintf(o, "        { unsigned char dg[16]; rt_md5(buf, %s, dg);\n"
                               "          if (rt_set_has(&TB, (const char *)dg, 16)) {\n"
                               "            pthread_mutex_lock(&MX);\n"
                               "            for (int h = 0; h < 16; h++) printf(\"%%02x\", dg[h]);\n"
                               "            putchar(':'); fwrite(buf, 1, %s, stdout); putchar('\\n');\n"
                               "            pthread_mutex_unlock(&MX); n++; } }\n", len, len);
    else if (match) fprintf(o, "        if (rt_set_has(&TB, (const char *)buf, %s))"
                               " { pthread_mutex_lock(&MX); fwrite(buf, 1, %s, stdout);"
                               " pthread_mutex_unlock(&MX); n++; }\n", len, lenp1);
    else if (count) fputs("        n++;\n", o);
    else            fprintf(o, "        fwrite(buf, 1, %s, stdout);\n", lenp1);
}

// The run() body for a pattern with a loop repeat X{a,b}. The repeat is one
// super-wheel of the outer odometer: pre wheels are the digits above it, post
// wheels the digits below, exactly the order the interpreter walks an embedded
// repeat ([b-c]{1,2}[x-y] runs bx by cx cy bbx...). Seeding decodes 'from' into
// a segment length rk and the body's digits; the step is a base-(product of the
// body) number that lengthens at a segment boundary. Within a segment every
// position sits at a fixed offset, so the common step delta-patches one byte --
// the fixed path's speed -- and only the rare carry into a longer segment (once
// per 26x of the members, for [a-z]{1,7}) rebuilds the variable-length tail.
static void emit_looprep_body(FILE *o, const struct build *B,
                              int count, int match, int hash, int progress, int acc)
{
    int P = B->lr_at, nw = B->nw, Q = nw - P, m = B->lr_nsw;
    const struct wheel *pre = B->w, *post = B->w + P, *sw = B->lr_sw;
    int a = B->lr_a, b = B->lr_b;

    int preoff[MAXW], PW = 0;
    for (int i = 0; i < P; i++) { preoff[i] = PW; PW += pre[i].L; }
    int soff[REP_SUBW], W = 0;
    for (int j = 0; j < m; j++) { soff[j] = W; W += sw[j].L; }
    int postoff[MAXW];
    for (int i = 0, q = 0; i < Q; i++) { postoff[i] = q; q += post[i].L; }

    // C = members of one body copy; segment k holds C^k, M the whole repeat.
    unsigned long long C = 1;
    for (int j = 0; j < m; j++) C *= (unsigned long long)sw[j].n;
    unsigned long long Cp = 1, M = 0;
    for (int k = 0; k < a; k++) Cp *= C;
    for (int k = a; k <= b; k++) { M += Cp; Cp *= C; }
    if (M == 0) M = 1;   // only reached with from==0 (N over 64 bits); keep %/ safe

    // --- seed from 'from' (post least significant, then the repeat, then pre) ---
    fputs("    unsigned long long f = from;\n", o);
    for (int i = Q - 1; i >= 0; i--)
        fprintf(o, "    int q%d = f %% %d; f /= %d;\n", i, post[i].n, post[i].n);
    fprintf(o, "    unsigned long long r = f %% %lluULL; f /= %lluULL;\n", M, M);
    for (int i = P - 1; i >= 0; i--)
        fprintf(o, "    int i%d = f %% %d; f /= %d;\n", i, pre[i].n, pre[i].n);
    fprintf(o, "    int rd[%d];\n", b * m);
    fprintf(o, "    int rk = %d;\n", a);
    fputs("    { unsigned long long seg = 1;\n", o);
    fprintf(o, "      for (int e = 0; e < %d; e++) seg *= %lluULL;\n", a, C);
    fprintf(o, "      while (rk <= %d) { if (r < seg) break; r -= seg; seg *= %lluULL; rk++; }\n", b, C);
    fputs("      for (int c = rk - 1; c >= 0; c--) {\n", o);
    for (int j = m - 1; j >= 0; j--)
        fprintf(o, "        rd[c*%d + %d] = r %% %d; r /= %d;\n", m, j, sw[j].n, sw[j].n);
    fputs("      }\n    }\n", o);
    if (acc) fputs("    unsigned long long n = 0;\n", o);
    fputs("    unsigned long long done = 0;\n", o);

    // --- lay the whole member ---
    for (int i = 0; i < P; i++) {
        char e[16]; snprintf(e, sizeof e, "i%d", i);
        fputs("    ", o); emit_lay(o, i, preoff[i], pre[i].L, e); fputc('\n', o);
    }
    fprintf(o, "    int p = %d;\n", PW);
    fputs("    for (int c = 0; c < rk; c++) {\n", o);
    for (int j = 0; j < m; j++) {
        if (sw[j].L == 1) fprintf(o, "        buf[p] = S%d[rd[c*%d + %d]]; p += 1;\n", j, m, j);
        else fprintf(o, "        memcpy(buf + p, S%d + rd[c*%d + %d] * %d, %d); p += %d;\n",
                     j, m, j, sw[j].L, sw[j].L, sw[j].L);
    }
    fputs("    }\n", o);
    for (int i = 0; i < Q; i++) {
        int t = P + i;
        if (post[i].L == 1) fprintf(o, "    buf[p] = A%d[q%d]; p += 1;\n", t, i);
        else fprintf(o, "    memcpy(buf + p, A%d + q%d * %d, %d); p += %d;\n",
                     t, i, post[i].L, post[i].L, post[i].L);
    }
    fputs("    buf[p] = '\\n';\n", o);

    // --- the odometer ---
    fputs("    for (;;) {\n", o);
    emit_sink(o, 0, match, count, hash, "p", "p + 1");
    fputs("        if (count && ++done == count) goto L_done;\n", o);
    if (progress) fputs("        if ((done & 0xffff) == 0) __atomic_store_n(prog, done, __ATOMIC_RELAXED);\n", o);

    // post wheels (least significant): the offset rides on rk*W but rk holds here.
    for (int i = Q - 1; i >= 0; i--) {
        int t = P + i, K = PW + postoff[i];
        fprintf(o, "        if (++q%d < %d) { ", i, post[i].n);
        if (post[i].L == 1) fprintf(o, "buf[rk*%d + %d] = A%d[q%d];", W, K, t, i);
        else fprintf(o, "memcpy(buf + (rk*%d + %d), A%d + q%d * %d, %d);", W, K, t, i, post[i].L, post[i].L);
        fprintf(o, " goto L_next; } q%d = 0; ", i);
        if (post[i].L == 1) fprintf(o, "buf[rk*%d + %d] = A%d[0];", W, K, t);
        else fprintf(o, "memcpy(buf + (rk*%d + %d), A%d, %d);", W, K, t, post[i].L);
        fputc('\n', o);
    }

    // the repeat body: a base-C odometer over rk*m digits, delta-patched. When
    // the body is a single wheel (the common [a-z]{1,7}), the least significant
    // copy turns nearly every step, so peel it out of the carry loop -- that
    // hot step is then a lone indexed patch, the fixed path's speed, and the
    // loop runs only on the rare carry.
    if (m == 1) {
        int R = sw[0].n, L = sw[0].L;
        if (a == 0) fputs("        if (rk) {\n", o);   // no last copy to peel at rk==0
        for (int pass = 0; pass < 2; pass++) {   // pass 0: the peeled last copy; 1: the loop body
            const char *ix = pass ? "c" : "rk-1";
            const char *ind = pass ? "            " : "        ";
            if (pass) fputs("        for (int c = rk - 2; c >= 0; c--) {\n", o);
            fprintf(o, "%sif (++rd[%s] < %d) { ", ind, ix, R);
            if (L == 1) fprintf(o, "buf[(%s)*%d + %d] = S0[rd[%s]];", ix, W, PW, ix);
            else fprintf(o, "memcpy(buf + ((%s)*%d + %d), S0 + rd[%s] * %d, %d);", ix, W, PW, ix, L, L);
            fprintf(o, " goto L_next; } rd[%s] = 0; ", ix);
            if (L == 1) fprintf(o, "buf[(%s)*%d + %d] = S0[0];", ix, W, PW);
            else fprintf(o, "memcpy(buf + ((%s)*%d + %d), S0, %d);", ix, W, PW, L);
            fputc('\n', o);
            if (pass) fputs("        }\n", o);
        }
        if (a == 0) fputs("        }\n", o);
    } else {
        fputs("        for (int c = rk - 1; c >= 0; c--) {\n", o);
        for (int j = m - 1; j >= 0; j--) {
            int K = PW + soff[j];
            fprintf(o, "            if (++rd[c*%d + %d] < %d) { ", m, j, sw[j].n);
            if (sw[j].L == 1) fprintf(o, "buf[c*%d + %d] = S%d[rd[c*%d + %d]];", W, K, j, m, j);
            else fprintf(o, "memcpy(buf + (c*%d + %d), S%d + rd[c*%d + %d] * %d, %d);", W, K, j, m, j, sw[j].L, sw[j].L);
            fputs(" goto L_next; }\n", o);
            fprintf(o, "            rd[c*%d + %d] = 0; ", m, j);
            if (sw[j].L == 1) fprintf(o, "buf[c*%d + %d] = S%d[0];", W, K, j);
            else fprintf(o, "memcpy(buf + (c*%d + %d), S%d, %d);", W, K, j, sw[j].L);
            fputc('\n', o);
        }
        fputs("        }\n", o);
    }

    // segment exhausted: grow to the next length, or roll the repeat over and
    // carry into the pre wheels. The tail's width changed, so relay it whole.
    fputs("        rk++;\n", o);
    fprintf(o, "        { int rolled = rk > %d;\n", b);
    fprintf(o, "          if (rolled) rk = %d;\n", a);
    fprintf(o, "          for (int t = 0; t < rk*%d; t++) rd[t] = 0;\n", m);
    fprintf(o, "          p = %d;\n", PW);
    fputs("          for (int c = 0; c < rk; c++) {\n", o);
    for (int j = 0; j < m; j++) {
        if (sw[j].L == 1) fprintf(o, "              buf[p] = S%d[rd[c*%d + %d]]; p += 1;\n", j, m, j);
        else fprintf(o, "              memcpy(buf + p, S%d + rd[c*%d + %d] * %d, %d); p += %d;\n", j, m, j, sw[j].L, sw[j].L, sw[j].L);
    }
    fputs("          }\n", o);
    for (int i = 0; i < Q; i++) {
        int t = P + i;
        if (post[i].L == 1) fprintf(o, "          buf[p] = A%d[q%d]; p += 1;\n", t, i);
        else fprintf(o, "          memcpy(buf + p, A%d + q%d * %d, %d); p += %d;\n", t, i, post[i].L, post[i].L, post[i].L);
    }
    fputs("          buf[p] = '\\n';\n", o);
    fputs("          if (rolled) {\n", o);
    for (int i = P - 1; i >= 0; i--) {
        char e[16]; snprintf(e, sizeof e, "i%d", i);
        fprintf(o, "            if (++i%d < %d) { ", i, pre[i].n);
        emit_lay(o, i, preoff[i], pre[i].L, e);
        fprintf(o, " goto L_next; } i%d = 0; ", i);
        emit_lay(o, i, preoff[i], pre[i].L, "0");
        fputc('\n', o);
    }
    fputs("            goto L_done;\n          }\n        }\n", o);
    fputs("        goto L_next;\n      L_next: ;\n    }\n  L_done:\n", o);
    if (acc) fputs("    *acc += n;\n", o);
}

// The generated program. Its core is run(from, count): seed the odometer to
// the member at index 'from' -- the mixed-radix digits of 'from', least
// significant wheel first -- then step it, handing 'count' members to the sink
// (0 = to the end). That shardable shape is the point: a thread, and one day a
// GPU lane, is just a run() over its own slice, so parallelism is built into the
// emitted code, not wrapped around it. Each wheel is a byte at buf[w]; a step
// rewrites only the byte that turned -- the delta render the tree walk cannot
// do -- and the most significant wheel carrying out is the end of the set.
//
// The count sink is the one that threads: it renders and tallies, sharing
// nothing, so main splits [0, N) across a thread each and sums the tallies. N is
// baked in ('nmemb', the member total as a decimal string, or NULL when it
// overflows 64 bits and cannot be split -- then the count runs on one thread).
// The write sink stays one ordered thread: several threads on one stdout would
// interleave, and generation to a pipe is I/O-bound anyway, so there is nothing
// to win there.
static void emit(FILE *o, const char *pattern, const struct build *B,
                 int sink, const char *nmemb, int verbose, int hash, int psec)
{
    struct wheel *w = B->w;
    int nw = B->nw;
    int count    = sink == SINK_COUNT;
    int match    = sink == SINK_MATCH;
    int dup      = sink == SINK_DUP;
    // How the match sink loads its targets: raw plaintext lines, or hex MD5
    // digests decoded to 16 bytes (keycracking, hash the candidate then probe).
    const char *load = hash ? "rt_load_hashes(&TB, argv[1], 16)"
                            : "rt_load(&TB, argv[1])";
    int acc      = count || match;              // sinks that tally into *acc
    int threaded = (acc || dup) && nmemb;       // split [0,N) when N fits 64 bits
    int rt       = match || dup;                // needs the embedded runtime
    int progress = psec > 0 && (count || match) && threaded;  // -p live reporter

    // Sizing. A member is rebuilt each step (not delta-patched) when a wheel is
    // variable-width, or a backreference copies a group -- either makes offsets
    // depend on the choice. bufcap is the most a member can hold; multi marks
    // memcpy (and string.h). Backref patterns cost bufcap the copied spans too,
    // so it is walked over the op list rather than the wheels.
    int variable = B->has_backref, multi = B->has_backref;
    for (int i = 0; i < nw; i++)
        if (w[i].L == 0) { variable = 1; multi = 1; }
        else if (w[i].L > 1) multi = 1;
    if (B->lr_active) {            // a loop repeat renders a variable-length tail
        variable = 1;
        for (int j = 0; j < B->lr_nsw; j++) if (B->lr_sw[j].L > 1) multi = 1;
    }

    int wmax[MAXW];                             // each wheel's longest branch
    for (int i = 0; i < nw; i++) {
        if (w[i].L) wmax[i] = w[i].L;
        else { int m = 0; for (int j = 0; j < w[i].n; j++) if (w[i].alen[j] > m) m = w[i].alen[j]; wmax[i] = m; }
    }
    int bufcap = 0;
    {
        int gpos[MAXW], glen[MAXW], p = 0;      // longest-member simulation
        for (int k = 0; k < B->nops; k++) {
            struct op op = B->ops[k];
            if      (op.kind == OP_LAY)   p += wmax[op.arg];
            else if (op.kind == OP_OPEN)  gpos[op.arg] = p;
            else if (op.kind == OP_CLOSE) glen[op.arg] = p - gpos[op.arg];
            else                          p += glen[op.arg];   // OP_COPY
        }
        bufcap = p;
    }
    if (B->lr_active) {           // the op walk misses the repeat's grown copies
        int PW = 0, W = 0, QW = 0;
        for (int i = 0; i < B->lr_at; i++) PW += w[i].L;
        for (int i = B->lr_at; i < nw; i++) QW += w[i].L;
        for (int j = 0; j < B->lr_nsw; j++) W += B->lr_sw[j].L;
        bufcap = PW + B->lr_b * W + QW;
    }
    int off[MAXW], TL = 0;
    if (!variable) for (int i = 0; i < nw; i++) { off[i] = TL; TL += w[i].L; }

    // Dedup is a closed form for the fixed case: each wheel owns a disjoint slice
    // of the member, so distinct = product of each wheel's distinct alternatives,
    // and the verdict follows without enumerating, at any size. A variable wheel
    // breaks that -- members alias across positions -- so those fall through to
    // the enumerate-and-hash path. Only -d -v enumerates in the fixed case, to
    // show the repeats, and only when the set is small enough.
    if (dup && !variable) {
        mpz_t total, distinct, dups;
        mpz_init_set_ui(total, 1);
        mpz_init_set_ui(distinct, 1);
        for (int i = 0; i < nw; i++) {
            mpz_mul_ui(total, total, (unsigned long)w[i].n);
            mpz_mul_ui(distinct, distinct, (unsigned long)wheel_distinct(&w[i]));
        }
        mpz_init(dups);
        mpz_sub(dups, total, distinct);
        int has = mpz_sgn(dups) > 0;
        int listable = verbose && has && mpz_cmp_ui(total, DUP_LIST_CAP) <= 0;
        if (!listable) {
            fputs("/* generated by rxejit from: ", o);
            emit_comment(o, pattern);
            fputs(" */\n#include <stdio.h>\n\nint main(void)\n{\n", o);
            if (has)
                gmp_fprintf(o, "    printf(\"%Zd members, %Zd distinct, %Zd duplicate%s"
                               " -- NOT distinct\\n\");\n", total, distinct, dups,
                               mpz_cmp_ui(dups, 1) == 0 ? "" : "s");
            else
                gmp_fprintf(o, "    printf(\"%Zd members, all distinct\\n\");\n", total);
            if (verbose && has)
                fputs("    fprintf(stderr, \"rxejit: too many members to list\\n\");\n", o);
            fprintf(o, "    return %d;\n}\n", has ? 1 : 0);
            mpz_clear(total); mpz_clear(distinct); mpz_clear(dups);
            return;
        }
        mpz_clear(total); mpz_clear(distinct); mpz_clear(dups);
        // listable: fall through to the enumerate-and-hash code below.
    }

    fputs("/* generated by rxejit from: ", o);
    emit_comment(o, pattern);
    fputs(" */\n#include <stdio.h>\n", o);
    if (multi && !rt) fputs("#include <string.h>\n", o);      // rt sinks get it via the runtime
    // match keeps a mutex for the rare hit print even on one thread, so pthread
    // comes in for it too; count and dup need pthread only when they thread.
    if (threaded || match) fputs("#include <stdlib.h>\n#include <pthread.h>\n#include <unistd.h>\n", o);
    if (progress) fputs("#include <time.h>\n", o);
    fputc('\n', o);

    if (rt) fputs(RXEJIT_RT, o), fputc('\n', o);
    if (match) {
        fputs("static struct rt_set TB;   /* the targets, read-only once loaded */\n", o);
        fputs("static pthread_mutex_t MX = PTHREAD_MUTEX_INITIALIZER;\n\n", o);
    }

    fputs(dup
        ? "static void run(unsigned long long from, unsigned long long count, struct rt_dup *d)\n{\n"
        : acc && progress
        ? "static void run(unsigned long long from, unsigned long long count, unsigned long long *acc, unsigned long long *prog)\n{\n"
        : acc
        ? "static void run(unsigned long long from, unsigned long long count, unsigned long long *acc)\n{\n"
        : "static void run(unsigned long long from, unsigned long long count)\n{\n", o);

    // Alphabet tables: each wheel's bytes, plus offset/length tables for a
    // variable wheel, whose branches are not evenly spaced.
    for (int i = 0; i < nw; i++) {
        int bytes = w[i].L ? w[i].n * w[i].L
                           : w[i].aoff[w[i].n - 1] + w[i].alen[w[i].n - 1];
        fprintf(o, "    static const unsigned char A%d[] = {", i);
        if (bytes == 0) fputs("0", o);              // all-empty branches; never read
        for (int j = 0; j < bytes; j++)
            fprintf(o, "%s%d", j ? "," : "", (unsigned char)w[i].base[j]);
        fputs("};\n", o);
        if (w[i].L == 0) {
            fprintf(o, "    static const int A%do[] = {", i);
            for (int j = 0; j < w[i].n; j++) fprintf(o, "%s%d", j ? "," : "", w[i].aoff[j]);
            fputs("};\n", o);
            fprintf(o, "    static const int A%dl[] = {", i);
            for (int j = 0; j < w[i].n; j++) fprintf(o, "%s%d", j ? "," : "", w[i].alen[j]);
            fputs("};\n", o);
        }
    }
    // The loop repeat's body sub-wheels get their own tables (all fixed width).
    for (int j = 0; B->lr_active && j < B->lr_nsw; j++) {
        const struct wheel *s = &B->lr_sw[j];
        fprintf(o, "    static const unsigned char S%d[] = {", j);
        for (int k = 0; k < s->n * s->L; k++)
            fprintf(o, "%s%d", k ? "," : "", (unsigned char)s->base[k]);
        fputs("};\n", o);
    }

    fprintf(o, "    unsigned char buf[%d];\n", bufcap + 1);

    if (B->lr_active) {
        emit_looprep_body(o, B, count, match, hash, progress, acc);
        fputs("}\n\n", o);
        goto after_run;
    }

    // Seed each wheel from 'from': digit = from %% radix, then from /= radix,
    // walking from the least significant wheel up, so the walk starts at 'from'.
    fputs("    unsigned long long f = from;\n", o);
    for (int i = nw - 1; i >= 0; i--)
        fprintf(o, "    int i%d = f %% %d; f /= %d;\n", i, w[i].n, w[i].n);
    if (acc) fputs("    unsigned long long n = 0;\n", o);
    fputs("    unsigned long long done = 0;\n", o);

    if (!variable) {
        // Fixed width: lay the member once, then a loop whose step delta-patches
        // only the byte(s) that turned. The length is a compile-time constant.
        char len[16], lenp1[16];
        snprintf(len, sizeof len, "%d", TL);
        snprintf(lenp1, sizeof lenp1, "%d", TL + 1);
        fprintf(o, "    buf[%d] = '\\n';\n", TL);
        for (int i = 0; i < nw; i++) {
            char e[16]; snprintf(e, sizeof e, "i%d", i);
            fputs("    ", o); emit_lay(o, i, off[i], w[i].L, e); fputc('\n', o);
        }
        fputs("    for (;;) {\n", o);
        emit_sink(o, dup, match, count, hash, len, lenp1);
        fputs("        if (count && ++done == count) break;\n", o);
        if (progress) fputs("        if ((done & 0xffff) == 0) __atomic_store_n(prog, done, __ATOMIC_RELAXED);\n", o);
        for (int i = nw - 1; i >= 0; i--) {
            char e[16]; snprintf(e, sizeof e, "i%d", i);
            fprintf(o, "        if (++i%d < %d) { ", i, w[i].n);
            emit_lay(o, i, off[i], w[i].L, e);
            fprintf(o, " continue; } i%d = 0; ", i);
            emit_lay(o, i, off[i], w[i].L, "0");
            fputc('\n', o);
        }
        fputs("        break;\n    }\n", o);
        if (acc) fputs("    *acc += n;\n", o);
    } else {
        // Variable width: a goto-threaded odometer. Each wheel keeps its current
        // byte position; the step jumps to the relay for the wheel that turned,
        // which rebuilds only the suffix from there. Since the least significant
        // wheel turns nearly every step, most members re-lay just a byte or two,
        // recovering the delta speed the fixed path has while still handling a
        // member whose width the choice decides. The relay blocks fall through,
        // so each wheel's lay is emitted once (the code is O(wheels), not O(n^2)).
        for (int i = 0; i < nw; i++) fprintf(o, "    int pos%d = 0;\n", i);
        for (int g = 0; g < B->ngroup; g++)
            fprintf(o, "    int g%d_pos = 0, g%d_len = 0;\n", g, g);
        fputs("    int p = 0;\n"
              "    goto R_init;\n"
              "  R_emit:\n"
              "    buf[p] = '\\n';\n", o);
        emit_sink(o, dup, match, count, hash, "p", "p + 1");
        fputs("    if (count && ++done == count) goto R_done;\n", o);
        if (progress) fputs("    if ((done & 0xffff) == 0) __atomic_store_n(prog, done, __ATOMIC_RELAXED);\n", o);
        for (int i = nw - 1; i >= 0; i--)
            fprintf(o, "    if (++i%d < %d) { p = pos%d; goto R_%d; } i%d = 0;\n",
                    i, w[i].n, i, i, i);
        fputs("    goto R_done;\n  R_init:\n", o);
        for (int k = 0; k < B->nops; k++) {
            struct op op = B->ops[k];
            int i = op.arg;
            if (op.kind == OP_LAY) {
                if (w[i].L)
                    fprintf(o, "  R_%d: pos%d = p; memcpy(buf + p, A%d + i%d * %d, %d); p += %d;\n",
                            i, i, i, i, w[i].L, w[i].L, w[i].L);
                else
                    fprintf(o, "  R_%d: pos%d = p; memcpy(buf + p, A%d + A%do[i%d], A%dl[i%d]);"
                               " p += A%dl[i%d];\n", i, i, i, i, i, i, i, i, i);
            } else if (op.kind == OP_OPEN) {
                fprintf(o, "        g%d_pos = p;\n", i);
            } else if (op.kind == OP_CLOSE) {
                fprintf(o, "        g%d_len = p - g%d_pos;\n", i, i);
            } else {  // OP_COPY
                fprintf(o, "        memcpy(buf + p, buf + g%d_pos, g%d_len); p += g%d_len;\n",
                        i, i, i);
            }
        }
        fputs("    goto R_emit;\n  R_done:\n", o);
        if (acc) fputs("    *acc += n;\n", o);
        fputs("    return;\n", o);
    }
    fputs("}\n\n", o);

after_run:
    if (dup) {
        // Each thread dedups its shard into its own set; main merges them and
        // reads the verdict off the total. Same asymmetry rxedup reports:
        // distinct is exact, a duplicate conclusive, out-of-memory inconclusive.
        fputs("static int report(struct rt_dup *d)\n{\n"
              "    unsigned long long total = d->total, distinct = d->used, dups = total - distinct;\n"
              "    if (d->oom) { printf(\"%llu members, all distinct so far, then out of memory -- inconclusive\\n\", total); return 2; }\n"
              "    if (dups) {\n"
              "        printf(\"%llu members, %llu distinct, %llu duplicate%s -- NOT distinct\\n\", total, distinct, dups, dups == 1 ? \"\" : \"s\");\n", o);
        if (verbose)
            fputs("        for (unsigned long i = 0; i < d->cap; i++)\n"
                  "            if (d->slot[i].key && d->slot[i].mult > 1)\n"
                  "                printf(\"  %llu x %.*s\\n\", d->slot[i].mult, (int)d->slot[i].len, d->slot[i].key);\n", o);
        fputs("        return 1;\n    }\n"
              "    printf(\"%llu members, all distinct\\n\", total);\n"
              "    return 0;\n}\n\n", o);

        if (threaded) {
            fprintf(o, "#define NMEMB %sULL\n#define MAXT  256\n\n", nmemb);
            fputs("struct shard { unsigned long long from, count; struct rt_dup dup; };\n\n"
                  "static void *worker(void *p)\n{\n"
                  "    struct shard *s = p;\n"
                  "    if (!rt_dup_init(&s->dup)) s->dup.oom = 1;\n"
                  "    run(s->from, s->count, &s->dup);\n"
                  "    return 0;\n"
                  "}\n\n"
                  "int main(int argc, char **argv)\n{\n"
                  "    long np = sysconf(_SC_NPROCESSORS_ONLN);\n"
                  "    int T = np < 1 ? 1 : (int)np;\n"
                  "    if (argc > 1) { int j = atoi(argv[1]); if (j > 0) T = j; }\n"
                  "    if (T > MAXT) T = MAXT;\n"
                  "    unsigned long long N = NMEMB;\n"
                  "    if (N == 0) { printf(\"0 members, all distinct\\n\"); return 0; }\n"
                  "    if (N < (unsigned long long)T) T = (int)N;\n"
                  "    struct shard sh[MAXT];\n"
                  "    pthread_t   tid[MAXT];\n"
                  "    unsigned long long base = N / (unsigned long long)T,\n"
                  "                       rem  = N % (unsigned long long)T, off = 0;\n"
                  "    for (int t = 0; t < T; t++) {\n"
                  "        sh[t].from = off;\n"
                  "        sh[t].count = base + ((unsigned long long)t < rem ? 1 : 0);\n"
                  "        off += sh[t].count;\n"
                  "    }\n"
                  "    for (int t = 1; t < T; t++) pthread_create(&tid[t], 0, worker, &sh[t]);\n"
                  "    worker(&sh[0]);\n"
                  "    for (int t = 1; t < T; t++) pthread_join(tid[t], 0);\n"
                  "    for (int t = 1; t < T; t++) rt_dup_absorb(&sh[0].dup, &sh[t].dup);\n"
                  "    int ret = report(&sh[0].dup);\n"
                  "    for (int t = 0; t < T; t++) rt_dup_free(&sh[t].dup);\n"
                  "    return ret;\n}\n", o);
        } else {
            fputs("int main(void)\n{\n"
                  "    struct rt_dup d;\n"
                  "    if (!rt_dup_init(&d)) { fprintf(stderr, \"rxejit: out of memory\\n\"); return 3; }\n"
                  "    run(0, 0, &d);\n"
                  "    int ret = report(&d);\n"
                  "    rt_dup_free(&d);\n"
                  "    return ret;\n}\n", o);
        }
    } else if (threaded) {
        // A thread per shard of [0, N). Count and match share the whole split;
        // only the setup (match loads the targets first, taking its jobs arg one
        // later) and the report (match to stderr, and it frees the set) differ.
        fprintf(o, "#define NMEMB %sULL\n#define MAXT  256\n", nmemb);
        if (progress) fprintf(o, "#define PSEC  %d\n", psec);
        fputc('\n', o);
        fputs(progress
            ? "struct shard { unsigned long long from, count, total, done; };\n\n"
            : "struct shard { unsigned long long from, count, total; };\n\n", o);
        fputs("static void *worker(void *p)\n{\n"
              "    struct shard *s = p;\n"
              "    s->total = 0;\n", o);
        fputs(progress
            ? "    s->done = 0;\n    run(s->from, s->count, &s->total, &s->done);\n"
            : "    run(s->from, s->count, &s->total);\n", o);
        fputs("    return 0;\n}\n\n", o);
        if (progress)
            // A monitor thread every PSEC seconds: sum the shards' progress (a
            // relaxed atomic, so no lock and no torn read TSan complains of),
            // and print percent / rate / elapsed / eta. Cancelled at the join so
            // a short run does not wait out a sleep.
            fputs("static struct shard *SH; static int NT;\n"
                  "static unsigned long long NALL; static int RUNNING = 1;\n"
                  "static double T0;\n"
                  "static double rt_now(void) { struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts); return ts.tv_sec + ts.tv_nsec / 1e9; }\n"
                  "static void *monitor(void *u)\n{\n"
                  "    (void)u;\n"
                  "    while (__atomic_load_n(&RUNNING, __ATOMIC_RELAXED)) {\n"
                  "        sleep(PSEC);\n"
                  "        if (!__atomic_load_n(&RUNNING, __ATOMIC_RELAXED)) break;\n"
                  "        unsigned long long d = 0;\n"
                  "        for (int t = 0; t < NT; t++) d += __atomic_load_n(&SH[t].done, __ATOMIC_RELAXED);\n"
                  "        double el = rt_now() - T0;\n"
                  "        double fr = NALL ? (double)d / (double)NALL : 0;\n"
                  "        double rate = el > 0 ? d / el : 0;\n"
                  "        double eta = fr > 0 ? el * (1 - fr) / fr : 0;\n"
                  "        fprintf(stderr, \"progress: %5.1f%%  %llu/%llu  %.3g/s  elapsed %.0fs  eta %.0fs\\n\",\n"
                  "                fr * 100, d, NALL, rate, el, eta);\n"
                  "    }\n"
                  "    return 0;\n}\n\n", o);
        fputs("int main(int argc, char **argv)\n{\n", o);
        if (match) {
            fputs("    if (argc < 2) { fprintf(stderr, \"usage: %s TARGETFILE [jobs]\\n\", argv[0]); return 2; }\n", o);
            fprintf(o, "    if (%s) { fprintf(stderr, \"rxejit: cannot read %%s\\n\", argv[1]); return 2; }\n", load);
            fputs("    int argoff = 2;\n", o);
        } else
            fputs("    int argoff = 1;\n", o);
        fputs("    long np = sysconf(_SC_NPROCESSORS_ONLN);\n"
              "    int T = np < 1 ? 1 : (int)np;\n"
              "    if (argc > argoff) { int j = atoi(argv[argoff]); if (j > 0) T = j; }\n"
              "    if (T > MAXT) T = MAXT;\n"
              "    unsigned long long N = NMEMB;\n", o);
        fputs(match
              ? "    if (N == 0) { fprintf(stderr, \"0 matches\\n\"); rt_set_free(&TB); return 0; }\n"
              : "    if (N == 0) { printf(\"0\\n\"); return 0; }\n", o);
        fputs("    if (N < (unsigned long long)T) T = (int)N;\n"
              "    struct shard sh[MAXT];\n"
              "    pthread_t   tid[MAXT];\n"
              "    unsigned long long base = N / (unsigned long long)T,\n"
              "                       rem  = N % (unsigned long long)T, off = 0;\n"
              "    for (int t = 0; t < T; t++) {\n"
              "        sh[t].from = off;\n"
              "        sh[t].count = base + ((unsigned long long)t < rem ? 1 : 0);\n", o);
        if (progress) fputs("        sh[t].done = 0;\n", o);
        fputs("        off += sh[t].count;\n"
              "    }\n", o);
        if (progress)
            fputs("    SH = sh; NT = T; NALL = N; T0 = rt_now();\n"
                  "    pthread_t montid; pthread_create(&montid, 0, monitor, 0);\n", o);
        fputs("    for (int t = 1; t < T; t++) pthread_create(&tid[t], 0, worker, &sh[t]);\n"
              "    worker(&sh[0]);\n"
              "    for (int t = 1; t < T; t++) pthread_join(tid[t], 0);\n", o);
        if (progress)
            fputs("    __atomic_store_n(&RUNNING, 0, __ATOMIC_RELAXED); pthread_cancel(montid); pthread_join(montid, 0);\n", o);
        fputs("    unsigned long long total = 0;\n"
              "    for (int t = 0; t < T; t++) total += sh[t].total;\n", o);
        fputs(match
              ? "    fprintf(stderr, \"%llu matches\\n\", total);\n    rt_set_free(&TB);\n"
              : "    printf(\"%llu\\n\", total);\n", o);
        fputs("    return 0;\n}\n", o);
    } else if (match) {
        // N over 64 bits: unsplittable, so one thread (the mutex uncontended).
        fputs("int main(int argc, char **argv)\n{\n"
              "    if (argc < 2) { fprintf(stderr, \"usage: %s TARGETFILE\\n\", argv[0]); return 2; }\n", o);
        fprintf(o, "    if (%s) { fprintf(stderr, \"rxejit: cannot read %%s\\n\", argv[1]); return 2; }\n", load);
        fputs("    unsigned long long acc = 0;\n"
              "    run(0, 0, &acc);\n"
              "    fprintf(stderr, \"%llu matches\\n\", acc);\n"
              "    rt_set_free(&TB);\n"
              "    return 0;\n}\n", o);
    } else if (count) {
        fputs("int main(void)\n{\n"
              "    unsigned long long acc = 0;\n"
              "    run(0, 0, &acc);\n"
              "    printf(\"%llu\\n\", acc);\n"
              "    return 0;\n}\n", o);
    } else {
        fputs("int main(void)\n{\n    run(0, 0);\n    return 0;\n}\n", o);
    }
}

// Emit a string s as a C string literal, escaped and broken across lines, so a
// block of generated source can be handed to clBuildProgram at runtime.
static void emit_c_string(FILE *o, const char *s)
{
    fputc('"', o);
    for (; *s; s++) {
        if      (*s == '\\') fputs("\\\\", o);
        else if (*s == '"')  fputs("\\\"", o);
        else if (*s == '\n') fputs("\\n\"\n\"", o);
        else                 fputc(*s, o);
    }
    fputc('"', o);
}

// The -G hybrid backend for a bare variable-count repeat X{a,b} ([a-z]{1,8}).
// The CPU owns the high wheels, the GPU a fixed block of low ones. For each
// member length k the CPU sweeps the high (k - GW) wheels, handing the GPU an
// opaque prefix (bytes, already laid); the GPU brute-forces GW low wheels,
// prepends the prefix, hashes, and keeps the rare hit. The kernel never knows
// what produced the prefix -- so the same engine will drive an arbitrary
// structure once a producer other than this odometer feeds it (the path to
// backrefs/alternations on the GPU). A kernel is built per member length via
// -D, so its width and MD5 length are compile-time constants -- the fixed
// path's speed, no runtime k. GW is picked so the low sweep is a fat batch
// (>= ~4M lanes); RXEJIT_GW overrides it for testing the prefix path on small
// masks. Hits are plaintext (length varies by length), re-hashed on the host.
static void emit_gpu_hybrid(FILE *o, const char *pattern, const struct build *B, int psec)
{
    const struct wheel *sw = &B->lr_sw[0];
    int R = sw->n, L = sw->L, a = B->lr_a, b = B->lr_b;
    int maxw = b * L;

    // GW: the low wheels the GPU sweeps. Smallest g whose R^g clears ~4M lanes,
    // capped at b; the env var forces it, to exercise the prefix path on a small
    // mask where the adaptive choice would put the whole thing on the GPU.
    long long gpow = 1; int gt = b;
    for (int g = 1; g <= b; g++) { gpow *= R; if (gpow >= (1 << 22)) { gt = g; break; } }
    const char *ge = getenv("RXEJIT_GW");
    if (ge) { int v = atoi(ge); if (v >= 1 && v <= b) gt = v; }

    char *ksrc = NULL; size_t ksz = 0;
    FILE *ms = open_memstream(&ksrc, &ksz);
    fputs(RXEJIT_CL, ms);
    fprintf(ms, "__constant uchar A0[] = {");
    for (int j = 0; j < R * L; j++) fprintf(ms, "%s%d", j ? "," : "", (unsigned char)sw->base[j]);
    fputs("};\n", ms);
    // T (total bytes), PLEN (prefix bytes), GW (low wheels) come in per length
    // via -D; R, L, MAXW, MAXHITS are the same for every length, baked here.
    fprintf(ms,
        "__kernel void crackL(ulong lo_base, ulong lo_N, __global const uchar *pfx,\n"
        "                     __global const uchar *tgt, uint ntgt,\n"
        "                     __global uint *hlen, __global uchar *hbuf, volatile __global uint *nhits)\n{\n"
        "    ulong j = lo_base + (ulong)get_global_id(0);\n    if (j >= lo_N) return;\n"
        "    uchar buf[T];\n"
        "    for (int i = 0; i < PLEN; i++) buf[i] = pfx[i];\n"
        "    ulong f = j;\n"
        "    for (int c = GW - 1; c >= 0; c--) { uint d = f %% %d; f /= %d;\n", R, R);
    if (L == 1) fputs("        buf[PLEN + c] = A0[d];\n", ms);
    else for (int t = 0; t < L; t++) fprintf(ms, "        buf[PLEN + c*%d + %d] = A0[d*%d + %d];\n", L, t, L, t);
    fprintf(ms,
        "    }\n    uchar dg[16]; cl_md5(buf, T, dg);\n"
        "    if (cl_tgt_has(tgt, ntgt, dg)) { uint s = atomic_inc(nhits);\n"
        "        if (s < %d) { hlen[s] = T; for (int t = 0; t < T; t++) hbuf[s*%d + t] = buf[t]; } }\n"
        "}\n", 1 << 20, maxw);
    fclose(ms);

    fputs("/* generated by rxejit -G (hybrid) from: ", o);
    emit_comment(o, pattern);
    fputs(" */\n#define CL_TARGET_OPENCL_VERSION 300\n"
          "#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n#include <time.h>\n#include <CL/cl.h>\n\n", o);
    fprintf(o, "#define PSEC %d\n", psec);
    fputs("static double rt_now(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec+t.tv_nsec/1e9;}\n", o);
    fputs(RXEJIT_RT, o); fputc('\n', o);

    fputs("static const char *KSRC =\n", o);
    emit_c_string(o, ksrc);
    fputs(";\n\n", o);
    free(ksrc);

    fprintf(o, "#define MAXW %d\n#define MAXHITS (1<<20)\n#define R %dULL\n#define L %d\n"
               "#define AMIN %d\n#define BMAX %d\n#define GT %d\n\n", maxw, R, L, a, b, gt);
    fprintf(o, "static const unsigned char A0h[] = {");
    for (int j = 0; j < R * L; j++) fprintf(o, "%s%d", j ? "," : "", (unsigned char)sw->base[j]);
    fputs("};\n\n", o);

    fputs("static int cmp16(const void *a, const void *b) { return memcmp(a, b, 16); }\n"
          "static unsigned char *load_targets(const char *path, unsigned *ntgt)\n{\n"
          "    FILE *fp = fopen(path, \"r\");\n    if (!fp) return NULL;\n"
          "    unsigned cap = 1024, n = 0;\n    unsigned char *t = malloc((size_t)cap * 16);\n"
          "    char line[256];\n"
          "    while (fgets(line, sizeof line, fp)) {\n"
          "        int ok = 1; unsigned char d[16];\n"
          "        for (int i = 0; i < 16; i++) { unsigned v;\n"
          "            if (sscanf(line + i*2, \"%2x\", &v) != 1) { ok = 0; break; } d[i] = (unsigned char)v; }\n"
          "        if (!ok) continue;\n"
          "        if (n == cap) { cap *= 2; t = realloc(t, (size_t)cap * 16); }\n"
          "        memcpy(t + (size_t)n * 16, d, 16); n++;\n"
          "    }\n    fclose(fp);\n    qsort(t, n, 16, cmp16);\n    *ntgt = n;\n    return t;\n}\n\n", o);

    fputs("#define CK(call) do { cl_int e_ = (call); if (e_ != CL_SUCCESS) {\\\n"
          "    fprintf(stderr, \"rxejit -G: %s failed (%d)\\n\", #call, e_); return 2; } } while (0)\n\n", o);

    fputs("int main(int argc, char **argv)\n{\n"
          "    if (argc < 2) { fprintf(stderr, \"usage: %s TARGETFILE\\n\", argv[0]); return 2; }\n"
          "    unsigned ntgt = 0;\n    unsigned char *tgt = load_targets(argv[1], &ntgt);\n"
          "    if (!tgt) { fprintf(stderr, \"rxejit -G: cannot read %s\\n\", argv[1]); return 2; }\n"
          "    if (ntgt == 0) { fprintf(stderr, \"0 matches\\n\"); return 0; }\n\n"
          "    cl_platform_id plat; cl_device_id dev; cl_int e;\n"
          "    if (clGetPlatformIDs(1, &plat, NULL) != CL_SUCCESS) { fprintf(stderr, \"rxejit -G: no OpenCL platform\\n\"); return 2; }\n"
          "    if (clGetDeviceIDs(plat, CL_DEVICE_TYPE_GPU, 1, &dev, NULL) != CL_SUCCESS) { fprintf(stderr, \"rxejit -G: no OpenCL GPU\\n\"); return 2; }\n"
          "    cl_context ctx = clCreateContext(NULL, 1, &dev, NULL, NULL, &e); CK(e);\n"
          "#if PSEC\n"
          "    cl_queue_properties qp[] = { CL_QUEUE_PROPERTIES, CL_QUEUE_PROFILING_ENABLE, 0 };\n"
          "    cl_command_queue q = clCreateCommandQueueWithProperties(ctx, dev, qp, &e); CK(e);\n"
          "#else\n"
          "    cl_command_queue q = clCreateCommandQueueWithProperties(ctx, dev, NULL, &e); CK(e);\n"
          "#endif\n\n"
          "    /* One program+kernel per member length k, its width and MD5 length baked. */\n"
          "    cl_kernel kern[BMAX + 1] = {0};\n"
          "    for (int k = AMIN; k <= BMAX; k++) {\n"
          "        int gw = k < GT ? k : GT, plen = (k - gw) * L, t = k * L;\n"
          "        char opts[96]; snprintf(opts, sizeof opts, \"-D T=%d -D PLEN=%d -D GW=%d\", t, plen, gw);\n"
          "        cl_program pr = clCreateProgramWithSource(ctx, 1, &KSRC, NULL, &e); CK(e);\n"
          "        if (clBuildProgram(pr, 1, &dev, opts, NULL, NULL) != CL_SUCCESS) {\n"
          "            size_t ls = 0; clGetProgramBuildInfo(pr, dev, CL_PROGRAM_BUILD_LOG, 0, NULL, &ls);\n"
          "            char *log = malloc(ls + 1); clGetProgramBuildInfo(pr, dev, CL_PROGRAM_BUILD_LOG, ls, log, NULL); log[ls] = 0;\n"
          "            fprintf(stderr, \"rxejit -G: build (k=%d) failed:\\n%s\\n\", k, log); return 2; }\n"
          "        kern[k] = clCreateKernel(pr, \"crackL\", &e); CK(e);\n"
          "    }\n\n"
          "    cl_mem mt = clCreateBuffer(ctx, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, (size_t)ntgt * 16, tgt, &e); CK(e);\n"
          "    cl_uint *hlen = calloc(MAXHITS, sizeof *hlen);\n    unsigned char *hbuf = calloc((size_t)MAXHITS, MAXW);\n"
          "    cl_uint nhits = 0;\n"
          "    cl_mem mhl = clCreateBuffer(ctx, CL_MEM_WRITE_ONLY, (size_t)MAXHITS * sizeof(cl_uint), NULL, &e); CK(e);\n"
          "    cl_mem mhb = clCreateBuffer(ctx, CL_MEM_WRITE_ONLY, (size_t)MAXHITS * MAXW, NULL, &e); CK(e);\n"
          "    cl_mem mn = clCreateBuffer(ctx, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, sizeof nhits, &nhits, &e); CK(e);\n"
          "    cl_mem mpfx = clCreateBuffer(ctx, CL_MEM_READ_ONLY, MAXW, NULL, &e); CK(e);\n"
          "    for (int k = AMIN; k <= BMAX; k++) {\n"
          "        CK(clSetKernelArg(kern[k], 2, sizeof mpfx, &mpfx));\n"
          "        CK(clSetKernelArg(kern[k], 3, sizeof mt, &mt));\n"
          "        CK(clSetKernelArg(kern[k], 4, sizeof ntgt, &ntgt));\n"
          "        CK(clSetKernelArg(kern[k], 5, sizeof mhl, &mhl));\n"
          "        CK(clSetKernelArg(kern[k], 6, sizeof mhb, &mhb));\n"
          "        CK(clSetKernelArg(kern[k], 7, sizeof mn, &mn));\n"
          "    }\n\n"
          "    cl_ulong TILE = 1ULL << 24;\n"
          "#if PSEC\n"
          "    /* Progress and GPU occupancy: candidates done vs the total, and the\n"
          "       fraction of wall time the device was actually executing a kernel\n"
          "       (from event profiling) -- a busy well under 100%% means the pipeline\n"
          "       is starving between launches. */\n"
          "    unsigned long long NALL = 0;\n"
          "    for (int k = AMIN; k <= BMAX; k++) { unsigned long long rk = 1; for (int i = 0; i < k; i++) rk *= R; NALL += rk; }\n"
          "    double t0 = rt_now(), tlast = t0; unsigned long long done = 0, gpu_ns = 0;\n"
          "#endif\n"
          "    for (int k = AMIN; k <= BMAX; k++) {\n"
          "        int gw = k < GT ? k : GT, hi = k - gw, plen = hi * L;\n"
          "        cl_ulong loN = 1; for (int i = 0; i < gw; i++) loN *= R;\n"
          "        cl_ulong npfx = 1; for (int i = 0; i < hi; i++) npfx *= R;\n"
          "        CK(clSetKernelArg(kern[k], 1, sizeof loN, &loN));\n"
          "        for (cl_ulong pi = 0; pi < npfx; pi++) {\n"
          "            unsigned char pbuf[MAXW]; cl_ulong pf = pi;\n"
          "            for (int hp = hi - 1; hp >= 0; hp--) { unsigned dd = pf % R; pf /= R;\n"
          "                for (int t = 0; t < L; t++) pbuf[hp*L + t] = A0h[dd*L + t]; }\n"
          "            if (plen) CK(clEnqueueWriteBuffer(q, mpfx, CL_TRUE, 0, plen, pbuf, 0, NULL, NULL));\n"
          "            for (cl_ulong base = 0; base < loN; base += TILE) {\n"
          "                cl_ulong n = (loN - base < TILE) ? (loN - base) : TILE;\n"
          "                size_t global = (size_t)((n + 255) / 256) * 256;\n"
          "                CK(clSetKernelArg(kern[k], 0, sizeof base, &base));\n"
          "#if PSEC\n"
          "                cl_event ev;\n"
          "                CK(clEnqueueNDRangeKernel(q, kern[k], 1, NULL, &global, NULL, 0, NULL, &ev));\n"
          "                CK(clFinish(q));\n"
          "                cl_ulong s0 = 0, s1 = 0;\n"
          "                clGetEventProfilingInfo(ev, CL_PROFILING_COMMAND_START, sizeof s0, &s0, NULL);\n"
          "                clGetEventProfilingInfo(ev, CL_PROFILING_COMMAND_END, sizeof s1, &s1, NULL);\n"
          "                gpu_ns += s1 - s0; done += n; clReleaseEvent(ev);\n"
          "                double now = rt_now();\n"
          "                if (now - tlast >= PSEC) {\n"
          "                    double el = now - t0, fr = NALL ? (double)done / NALL : 0;\n"
          "                    fprintf(stderr, \"gpu: %5.1f%%  %llu/%llu  %.3g/s  eta %.0fs  busy %.0f%%\\n\",\n"
          "                            fr * 100, done, NALL, el > 0 ? done / el : 0,\n"
          "                            fr > 0 ? el * (1 - fr) / fr : 0, el > 0 ? (gpu_ns / 1e9) / el * 100 : 0);\n"
          "                    tlast = now;\n"
          "                }\n"
          "#else\n"
          "                CK(clEnqueueNDRangeKernel(q, kern[k], 1, NULL, &global, NULL, 0, NULL, NULL));\n"
          "                CK(clFinish(q));\n"
          "#endif\n"
          "            }\n"
          "        }\n"
          "    }\n"
          "    CK(clEnqueueReadBuffer(q, mn, CL_TRUE, 0, sizeof nhits, &nhits, 0, NULL, NULL));\n"
          "    unsigned got = nhits < MAXHITS ? nhits : MAXHITS;\n"
          "    CK(clEnqueueReadBuffer(q, mhl, CL_TRUE, 0, (size_t)got * sizeof(cl_uint), hlen, 0, NULL, NULL));\n"
          "    CK(clEnqueueReadBuffer(q, mhb, CL_TRUE, 0, (size_t)got * MAXW, hbuf, 0, NULL, NULL));\n\n"
          "    for (unsigned i = 0; i < got; i++) {\n"
          "        unsigned char *p = hbuf + (size_t)i * MAXW, dg[16];\n"
          "        rt_md5(p, hlen[i], dg);\n"
          "        for (int h = 0; h < 16; h++) printf(\"%02x\", dg[h]);\n"
          "        putchar(':'); fwrite(p, 1, hlen[i], stdout); putchar('\\n');\n"
          "    }\n"
          "    if (nhits > MAXHITS) fprintf(stderr, \"rxejit -G: %u hits, only %u recorded\\n\", nhits, MAXHITS);\n"
          "    fprintf(stderr, \"%u matches\\n\", nhits);\n"
          "    free(tgt); free(hlen); free(hbuf);\n    return 0;\n}\n", o);
}

// The -G generic backend: any finite pattern whose tail is a run of independent
// fixed classes. rxejit (which has the enumerator) is the producer -- it
// stride-seeks the pattern and writes each high prefix to a file; this generated
// consumer is the GPU half. For each prefix it sweeps the fixed low block (G
// distinct wheels), prepends the prefix, hashes, keeps the hit. The head can be
// anything rxe enumerates -- uneven alternations, dictionaries, head-side
// backrefs -- so -G reaches far past a plain mask. A kernel is built per total
// member length on demand (its width and MD5 length baked), so every sweep runs
// at the fixed path's speed. Hits are plaintext, re-hashed on the host.
// The widest member in bytes -- backref copies included, walked over the op list
// the way emit()'s bufcap is. The generic path needs it for the buffer cap and
// the plaintext hit-row stride, since a head backref lays bytes no wheel counts.
static int gpu_maxwidth(const struct build *B)
{
    int wmax[MAXW];
    for (int i = 0; i < B->nw; i++) {
        if (B->w[i].L) wmax[i] = B->w[i].L;
        else { int m = 0; for (int j = 0; j < B->w[i].n; j++) if (B->w[i].alen[j] > m) m = B->w[i].alen[j]; wmax[i] = m; }
    }
    int gpos[MAXW], glen[MAXW], p = 0;
    for (int k = 0; k < B->nops; k++) {
        struct op op = B->ops[k];
        if      (op.kind == OP_LAY)   p += wmax[op.arg];
        else if (op.kind == OP_OPEN)  gpos[op.arg] = p;
        else if (op.kind == OP_CLOSE) glen[op.arg] = p - gpos[op.arg];
        else                          p += glen[op.arg];      // OP_COPY
    }
    return p;
}

static void emit_gpu_generic(FILE *o, const char *pattern, const struct build *B, int G, int psec)
{
    int nw = B->nw;
    struct wheel *lw = B->w + (nw - G);          // the G low wheels (the tail)
    int lwoff[64], lowwidth = 0;
    for (int g = 0; g < G; g++) { lwoff[g] = lowwidth; lowwidth += lw[g].L; }
    unsigned long long lon = 1;
    for (int g = 0; g < G; g++) lon *= (unsigned long long)lw[g].n;
    int maxw = gpu_maxwidth(B);
    if (maxw < 1) maxw = 1;

    char *ksrc = NULL; size_t ksz = 0;
    FILE *ms = open_memstream(&ksrc, &ksz);
    fputs(RXEJIT_CL, ms);
    for (int g = 0; g < G; g++) {
        fprintf(ms, "__constant uchar A%d[] = {", g);
        for (int j = 0; j < lw[g].n * lw[g].L; j++) fprintf(ms, "%s%d", j ? "," : "", (unsigned char)lw[g].base[j]);
        fputs("};\n", ms);
    }
    // T (total bytes) and PLEN (prefix bytes) come in per length via -D; the low
    // block (G wheels, their radices and offsets) is baked straight-line.
    fputs("__kernel void crackG(ulong lo_base, ulong lo_N, __global const uchar *pfx,\n"
          "                     __global const uchar *tgt, uint ntgt,\n"
          "                     __global uint *hlen, __global uchar *hbuf, volatile __global uint *nhits)\n{\n"
          "    ulong j = lo_base + (ulong)get_global_id(0);\n    if (j >= lo_N) return;\n"
          "    uchar buf[T];\n"
          "    for (int i = 0; i < PLEN; i++) buf[i] = pfx[i];\n"
          "    ulong f = j;\n", ms);
    for (int g = G - 1; g >= 0; g--) fprintf(ms, "    uint d%d = f %% %d; f /= %d;\n", g, lw[g].n, lw[g].n);
    for (int g = 0; g < G; g++) {
        if (lw[g].L == 1) fprintf(ms, "    buf[PLEN + %d] = A%d[d%d];\n", lwoff[g], g, g);
        else for (int t = 0; t < lw[g].L; t++)
            fprintf(ms, "    buf[PLEN + %d] = A%d[d%d*%d + %d];\n", lwoff[g] + t, g, g, lw[g].L, t);
    }
    fprintf(ms,
        "    uchar dg[16]; cl_md5(buf, T, dg);\n"
        "    if (cl_tgt_has(tgt, ntgt, dg)) { uint s = atomic_inc(nhits);\n"
        "        if (s < %d) { hlen[s] = T; for (int t = 0; t < T; t++) hbuf[s*%d + t] = buf[t]; } }\n"
        "}\n", 1 << 20, maxw);
    fclose(ms);

    fputs("/* generated by rxejit -G (generic) from: ", o);
    emit_comment(o, pattern);
    fputs(" */\n#define CL_TARGET_OPENCL_VERSION 300\n"
          "#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n#include <time.h>\n#include <CL/cl.h>\n\n", o);
    fprintf(o, "#define PSEC %d\n", psec);
    fputs("static double rt_now(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec+t.tv_nsec/1e9;}\n", o);
    fputs(RXEJIT_RT, o); fputc('\n', o);

    fputs("static const char *KSRC =\n", o);
    emit_c_string(o, ksrc);
    fputs(";\n\n", o);
    free(ksrc);

    fprintf(o, "#define MAXW %d\n#define MAXHITS (1<<20)\n#define LOWWIDTH %d\n#define LON %lluULL\n\n",
            maxw, lowwidth, lon);

    fputs("static int cmp16(const void *a, const void *b) { return memcmp(a, b, 16); }\n"
          "static unsigned char *load_targets(const char *path, unsigned *ntgt)\n{\n"
          "    FILE *fp = fopen(path, \"r\");\n    if (!fp) return NULL;\n"
          "    unsigned cap = 1024, n = 0;\n    unsigned char *t = malloc((size_t)cap * 16);\n"
          "    char line[256];\n"
          "    while (fgets(line, sizeof line, fp)) {\n"
          "        int ok = 1; unsigned char d[16];\n"
          "        for (int i = 0; i < 16; i++) { unsigned v;\n"
          "            if (sscanf(line + i*2, \"%2x\", &v) != 1) { ok = 0; break; } d[i] = (unsigned char)v; }\n"
          "        if (!ok) continue;\n"
          "        if (n == cap) { cap *= 2; t = realloc(t, (size_t)cap * 16); }\n"
          "        memcpy(t + (size_t)n * 16, d, 16); n++;\n"
          "    }\n    fclose(fp);\n    qsort(t, n, 16, cmp16);\n    *ntgt = n;\n    return t;\n}\n\n", o);

    fputs("#define CK(call) do { cl_int e_ = (call); if (e_ != CL_SUCCESS) {\\\n"
          "    fprintf(stderr, \"rxejit -G: %s failed (%d)\\n\", #call, e_); return 2; } } while (0)\n\n", o);

    fputs("static cl_context ctx; static cl_device_id dev;\n"
          "static cl_kernel kern[MAXW + 1];   /* one per total member length, built on demand */\n"
          "static cl_kernel kernel_for(int T) {\n"
          "    if (kern[T]) return kern[T];\n"
          "    cl_int e; char opts[96]; snprintf(opts, sizeof opts, \"-D T=%d -D PLEN=%d\", T, T - LOWWIDTH);\n"
          "    cl_program pr = clCreateProgramWithSource(ctx, 1, &KSRC, NULL, &e);\n"
          "    if (clBuildProgram(pr, 1, &dev, opts, NULL, NULL) != CL_SUCCESS) {\n"
          "        size_t ls = 0; clGetProgramBuildInfo(pr, dev, CL_PROGRAM_BUILD_LOG, 0, NULL, &ls);\n"
          "        char *log = malloc(ls + 1); clGetProgramBuildInfo(pr, dev, CL_PROGRAM_BUILD_LOG, ls, log, NULL); log[ls] = 0;\n"
          "        fprintf(stderr, \"rxejit -G: build (T=%d) failed:\\n%s\\n\", T, log); exit(2); }\n"
          "    kern[T] = clCreateKernel(pr, \"crackG\", &e);\n    return kern[T];\n}\n\n", o);

    fputs("int main(int argc, char **argv)\n{\n"
          "    if (argc < 3) { fprintf(stderr, \"usage: %s TARGETFILE PREFIXFILE\\n\", argv[0]); return 2; }\n"
          "    unsigned ntgt = 0;\n    unsigned char *tgt = load_targets(argv[1], &ntgt);\n"
          "    if (!tgt) { fprintf(stderr, \"rxejit -G: cannot read %s\\n\", argv[1]); return 2; }\n"
          "    FILE *pf = fopen(argv[2], \"rb\");\n"
          "    if (!pf) { fprintf(stderr, \"rxejit -G: cannot read %s\\n\", argv[2]); return 2; }\n"
          "    if (ntgt == 0) { fprintf(stderr, \"0 matches\\n\"); return 0; }\n\n"
          "    cl_platform_id plat; cl_int e;\n"
          "    if (clGetPlatformIDs(1, &plat, NULL) != CL_SUCCESS) { fprintf(stderr, \"rxejit -G: no OpenCL platform\\n\"); return 2; }\n"
          "    if (clGetDeviceIDs(plat, CL_DEVICE_TYPE_GPU, 1, &dev, NULL) != CL_SUCCESS) { fprintf(stderr, \"rxejit -G: no OpenCL GPU\\n\"); return 2; }\n"
          "    ctx = clCreateContext(NULL, 1, &dev, NULL, NULL, &e); CK(e);\n"
          "#if PSEC\n"
          "    cl_queue_properties qp[] = { CL_QUEUE_PROPERTIES, CL_QUEUE_PROFILING_ENABLE, 0 };\n"
          "    cl_command_queue q = clCreateCommandQueueWithProperties(ctx, dev, qp, &e); CK(e);\n"
          "#else\n"
          "    cl_command_queue q = clCreateCommandQueueWithProperties(ctx, dev, NULL, &e); CK(e);\n"
          "#endif\n\n"
          "    cl_mem mt = clCreateBuffer(ctx, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, (size_t)ntgt * 16, tgt, &e); CK(e);\n"
          "    cl_uint *hlen = calloc(MAXHITS, sizeof *hlen); unsigned char *hbuf = calloc((size_t)MAXHITS, MAXW);\n"
          "    cl_uint nhits = 0;\n"
          "    cl_mem mhl = clCreateBuffer(ctx, CL_MEM_WRITE_ONLY, (size_t)MAXHITS * sizeof(cl_uint), NULL, &e); CK(e);\n"
          "    cl_mem mhb = clCreateBuffer(ctx, CL_MEM_WRITE_ONLY, (size_t)MAXHITS * MAXW, NULL, &e); CK(e);\n"
          "    cl_mem mn = clCreateBuffer(ctx, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, sizeof nhits, &nhits, &e); CK(e);\n"
          "    cl_mem mpfx = clCreateBuffer(ctx, CL_MEM_READ_ONLY, MAXW, NULL, &e); CK(e);\n\n"
          "    cl_ulong TILE = 1ULL << 24, loN = LON;\n"
          "#if PSEC\n    double t0 = rt_now(), tlast = t0; unsigned long long gpu_ns = 0, done = 0;\n#endif\n"
          "    unsigned char rec[MAXW + 1]; int plen;\n"
          "    while (fread(rec, 1, 1, pf) == 1 && (plen = rec[0]) >= 0) {\n"
          "        if (plen > MAXW) { fprintf(stderr, \"rxejit -G: bad prefix\\n\"); return 2; }\n"
          "        if (plen && fread(rec, 1, plen, pf) != (size_t)plen) break;\n"
          "        int T = plen + LOWWIDTH;\n"
          "        cl_kernel k = kernel_for(T);\n"
          "        if (plen) CK(clEnqueueWriteBuffer(q, mpfx, CL_TRUE, 0, plen, rec, 0, NULL, NULL));\n"
          "        CK(clSetKernelArg(k, 1, sizeof loN, &loN));\n"
          "        CK(clSetKernelArg(k, 2, sizeof mpfx, &mpfx));\n"
          "        CK(clSetKernelArg(k, 3, sizeof mt, &mt));\n"
          "        CK(clSetKernelArg(k, 4, sizeof ntgt, &ntgt));\n"
          "        CK(clSetKernelArg(k, 5, sizeof mhl, &mhl));\n"
          "        CK(clSetKernelArg(k, 6, sizeof mhb, &mhb));\n"
          "        CK(clSetKernelArg(k, 7, sizeof mn, &mn));\n"
          "        for (cl_ulong base = 0; base < loN; base += TILE) {\n"
          "            cl_ulong n = (loN - base < TILE) ? (loN - base) : TILE;\n"
          "            size_t global = (size_t)((n + 255) / 256) * 256;\n"
          "            CK(clSetKernelArg(k, 0, sizeof base, &base));\n"
          "#if PSEC\n"
          "            cl_event ev;\n"
          "            CK(clEnqueueNDRangeKernel(q, k, 1, NULL, &global, NULL, 0, NULL, &ev)); CK(clFinish(q));\n"
          "            cl_ulong s0 = 0, s1 = 0;\n"
          "            clGetEventProfilingInfo(ev, CL_PROFILING_COMMAND_START, sizeof s0, &s0, NULL);\n"
          "            clGetEventProfilingInfo(ev, CL_PROFILING_COMMAND_END, sizeof s1, &s1, NULL);\n"
          "            gpu_ns += s1 - s0; done += n; clReleaseEvent(ev);\n"
          "            double now = rt_now();\n"
          "            if (now - tlast >= PSEC) { double el = now - t0;\n"
          "                fprintf(stderr, \"gpu: %llu done  %.3g/s  busy %.0f%%\\n\", done, el > 0 ? done / el : 0,\n"
          "                        el > 0 ? (gpu_ns / 1e9) / el * 100 : 0); tlast = now; }\n"
          "#else\n"
          "            CK(clEnqueueNDRangeKernel(q, k, 1, NULL, &global, NULL, 0, NULL, NULL)); CK(clFinish(q));\n"
          "#endif\n"
          "        }\n"
          "    }\n"
          "    fclose(pf);\n"
          "    CK(clEnqueueReadBuffer(q, mn, CL_TRUE, 0, sizeof nhits, &nhits, 0, NULL, NULL));\n"
          "    unsigned got = nhits < MAXHITS ? nhits : MAXHITS;\n"
          "    CK(clEnqueueReadBuffer(q, mhl, CL_TRUE, 0, (size_t)got * sizeof(cl_uint), hlen, 0, NULL, NULL));\n"
          "    CK(clEnqueueReadBuffer(q, mhb, CL_TRUE, 0, (size_t)got * MAXW, hbuf, 0, NULL, NULL));\n"
          "    for (unsigned i = 0; i < got; i++) {\n"
          "        unsigned char *p = hbuf + (size_t)i * MAXW, dg[16];\n"
          "        rt_md5(p, hlen[i], dg);\n"
          "        for (int h = 0; h < 16; h++) printf(\"%02x\", dg[h]);\n"
          "        putchar(':'); fwrite(p, 1, hlen[i], stdout); putchar('\\n');\n"
          "    }\n"
          "    if (nhits > MAXHITS) fprintf(stderr, \"rxejit -G: %u hits, only %u recorded\\n\", nhits, MAXHITS);\n"
          "    fprintf(stderr, \"%u matches\\n\", nhits);\n"
          "    free(tgt); free(hlen); free(hbuf);\n    return 0;\n}\n", o);
}

// Run argv to completion, its stdout inherited so a generated enumerator's
// output flows straight through. Returns the exit status, or -1 if it could
// not be run at all.
static int spawn(char *const argv[])
{
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) { execvp(argv[0], argv); _exit(127); }
    int st;
    if (waitpid(pid, &st, 0) < 0) return -1;
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

// Emit the C to a temp file, compile it with $CC (or cc) at -O2, run it. The
// members -- or the count -- come out on our stdout. Returns a process exit
// code.
static int compile_and_run(const char *pattern, const struct build *B,
                           int sink, const char *nmemb, const char *jobs,
                           const char *matchfile, int verbose, int hash, int psec,
                           int gpu)
{
    char dir[] = "/tmp/rxejit.XXXXXX";
    if (!mkdtemp(dir)) { perror("rxejit: mkdtemp"); return 2; }

    char src[64], exe[64];
    snprintf(src, sizeof src, "%s/m.c", dir);
    snprintf(exe, sizeof exe, "%s/m", dir);

    int ret = 0;
    FILE *f = fopen(src, "w");
    if (!f) { perror("rxejit: fopen"); ret = 2; goto done; }
    if (gpu)   emit_gpu_hybrid(f, pattern, B, psec);   // gpu == 2, the loop repeat
    else       emit(f, pattern, B, sink, nmemb, verbose, hash, psec);
    fclose(f);

    const char *cc = getenv("CC");
    if (!cc || !*cc) cc = "cc";
    char *cargv_cpu[] = { (char *)cc, "-O2", "-pthread", src, "-o", exe, NULL };
    char *cargv_gpu[] = { (char *)cc, "-O2", src, "-o", exe, "-lOpenCL", NULL };
    int rc = spawn(gpu ? cargv_gpu : cargv_cpu);
    if (rc != 0) {
        fprintf(stderr, "rxejit: the C compiler (%s) failed\n", cc);
        ret = 2; goto done;
    }
    // Argument order the generated program expects: the match file first (if
    // any), then the thread count (if any). So write gets none, count gets
    // jobs, match gets the file, threaded match gets the file then jobs.
    char *rargv[4];
    int k = 0;
    rargv[k++] = exe;
    if (matchfile) rargv[k++] = (char *)matchfile;
    if (jobs)      rargv[k++] = (char *)jobs;
    rargv[k] = NULL;
    // Pass the enumerator's own exit status back up -- the dup sink reports its
    // verdict there (0 distinct, 1 a duplicate, 2 inconclusive).
    int r = spawn(rargv);
    if (r < 0) { fprintf(stderr, "rxejit: could not run the enumerator\n"); ret = 2; }
    else       ret = r;

done:
    unlink(src);
    unlink(exe);
    rmdir(dir);
    return ret;
}

// The generic -G producer: rxejit itself. The low block is the last G wheels;
// members group into runs of P_low that share a prefix (the low wheels are the
// least significant, independent factor), so seeking to every P_low-th member
// and stripping the low bytes yields each distinct prefix. Written to a file the
// GPU consumer reads: one record of a length byte then that many prefix bytes.
static int write_prefix_file(struct rxe *rxe, const struct build *B, int G, const char *path)
{
    int nw = B->nw, lowwidth = 0;
    mpz_t Pl; mpz_init_set_ui(Pl, 1);
    for (int g = nw - G; g < nw; g++) { mpz_mul_ui(Pl, Pl, (unsigned long)B->w[g].n); lowwidth += B->w[g].L; }

    FILE *f = fopen(path, "wb");
    if (!f) { mpz_clear(Pl); return -1; }
    mpz_t np, idx, i;
    mpz_init(np); mpz_init(idx); mpz_init_set_ui(i, 0);
    mpz_tdiv_q(np, rxe->nitems, Pl);          // number of prefixes = N / P_low
    char buf[4096];
    int rc = 0;
    for (; mpz_cmp(i, np) < 0; mpz_add_ui(i, i, 1)) {
        mpz_mul(idx, i, Pl);
        if (rxe_seek(rxe, idx)) { rc = -1; break; }
        char *end = rxe_current(buf, (int)sizeof buf - 1, rxe);
        int mlen = (int)(end - buf), plen = mlen - lowwidth;
        if (plen < 0 || plen > 255) { rc = -1; break; }
        unsigned char lb = (unsigned char)plen;
        if (fwrite(&lb, 1, 1, f) != 1 || (plen && fwrite(buf, 1, (size_t)plen, f) != (size_t)plen)) { rc = -1; break; }
    }
    mpz_clear(Pl); mpz_clear(np); mpz_clear(idx); mpz_clear(i);
    fclose(f);
    return rc;
}

// Generate the generic consumer, compile it (-lOpenCL), have rxejit write the
// prefix file, then run the consumer over (targets, prefixes).
static int compile_and_run_generic(const char *pattern, const struct build *B,
                                   struct rxe *rxe, int G, const char *matchfile, int psec)
{
    char dir[] = "/tmp/rxejit.XXXXXX";
    if (!mkdtemp(dir)) { perror("rxejit: mkdtemp"); return 2; }
    char src[64], exe[64], pfx[64];
    snprintf(src, sizeof src, "%s/m.c", dir);
    snprintf(exe, sizeof exe, "%s/m", dir);
    snprintf(pfx, sizeof pfx, "%s/p.bin", dir);

    int ret = 0;
    FILE *f = fopen(src, "w");
    if (!f) { perror("rxejit: fopen"); ret = 2; goto done; }
    emit_gpu_generic(f, pattern, B, G, psec);
    fclose(f);

    const char *cc = getenv("CC");
    if (!cc || !*cc) cc = "cc";
    char *cargv[] = { (char *)cc, "-O2", src, "-o", exe, "-lOpenCL", NULL };
    if (spawn(cargv) != 0) { fprintf(stderr, "rxejit: the C compiler (%s) failed\n", cc); ret = 2; goto done; }

    if (write_prefix_file(rxe, B, G, pfx)) { fprintf(stderr, "rxejit: could not enumerate the prefixes\n"); ret = 2; goto done; }

    char *rargv[] = { exe, (char *)matchfile, pfx, NULL };
    int r = spawn(rargv);
    if (r < 0) { fprintf(stderr, "rxejit: could not run the enumerator\n"); ret = 2; }
    else       ret = r;

done:
    unlink(src); unlink(exe); unlink(pfx); rmdir(dir);
    return ret;
}

/* The same [:name:] word lists rxenum reads: a name.dict file, one word per
 * line, looked up in the -D directories then the current one. Resolution runs
 * at parse time; bake_dict then copies the words it needs. Lifted from rxedup. */

#define MAX_DICT_DIRS 16
static const char *dict_dirs[MAX_DICT_DIRS];
static int         ndict_dirs;

static char **load_dict_file(const char *path, int *nwords)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) return NULL;
    int cap = 64, n = 0;
    char **words = malloc(cap * sizeof *words);
    char line[1024];
    while (fgets(line, sizeof line, fp)) {
        int len = strlen(line);
        while (len && (line[len-1] == '\n' || line[len-1] == '\r')) line[--len] = 0;
        if (n == cap) { cap *= 2; words = realloc(words, cap * sizeof *words); }
        words[n] = malloc(len + 1);
        memcpy(words[n], line, len + 1);
        n++;
    }
    fclose(fp);
    *nwords = n;
    return words;
}

static int dict_resolver(const char *name)
{
    for (int d = -1; d < ndict_dirs; d++) {
        char path[1024];
        const char *dir = d < 0 ? "." : dict_dirs[d];
        snprintf(path, sizeof path, "%s/%s.dict", dir, name);
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

int main(int argc, char **argv)
{
    const char *prog = argc > 0 ? argv[0] : "rxejit";
    int emit_only = 0, sink = SINK_WRITE, verbose = 0, hash = 0, psec = 0, gpu = 0, opt;
    const char *jobs = NULL;              // thread count, forwarded to the exe
    const char *matchfile = NULL;         // target file for -m

    while ((opt = getopt(argc, argv, "SGndvj:m:H:D:p:h")) != -1) {
        switch (opt) {
            case 'S': emit_only = 1; break;
            case 'G': gpu = 1; break;
            case 'p': psec = atoi(optarg);
                      if (psec < 1) { fprintf(stderr, "%s: -p needs seconds >= 1\n", prog); return 2; }
                      break;
            case 'n': sink = SINK_COUNT; break;
            case 'd': sink = SINK_DUP; break;
            case 'v': verbose = 1; break;
            case 'j': jobs = optarg; break;
            case 'm': sink = SINK_MATCH; matchfile = optarg; break;
            case 'D': if (ndict_dirs < MAX_DICT_DIRS) dict_dirs[ndict_dirs++] = optarg; break;
            case 'H': sink = SINK_MATCH; hash = 1;
                      if (strcmp(optarg, "md5") != 0) {
                          fprintf(stderr, "%s: -H: only md5 is supported\n", prog);
                          return 2;
                      }
                      break;
            case 'h':
            default:
                fprintf(stderr,
"usage: %s [-S] [-n | -m file [-H md5] | -d [-v]] [-j jobs] REGEX\n"
"  Compile the set REGEX describes into C and run it, enumerating the members.\n"
"  Handles any finite pattern -- masks, alternations, bounded repeats,\n"
"  dictionaries, backreferences. Only an unbounded (infinite) repeat, or a set\n"
"  too large to unroll, is declined, with a reason.\n"
"    -S       print the generated C to stdout instead of compiling and running it.\n"
"    -n       count the members rather than print them (times the walk, no I/O).\n"
"    -m file  print only the members present in 'file' (one target per line):\n"
"             the mask is a keyspace, 'file' the set to sift it against.\n"
"    -H md5   with -m, 'file' holds MD5 hex digests: hash each candidate and\n"
"             print <digest>:<plaintext> for a hit -- keycracking.\n"
"    -d       report duplicate members: hash each into a per-thread set and\n"
"             merge at the join. Exit 0 if all distinct, 1 if a duplicate.\n"
"    -v       with -d, list the repeated members and their counts.\n"
"    -j jobs  threads for -n, -m and -d (default: one per CPU). Printing stays\n"
"             single-threaded and ordered.\n"
"    -p sec   every 'sec' seconds print progress to stderr -- percent done,\n"
"             rate, elapsed and ETA (the threaded -n and -m runs, and -G, which\n"
"             also reports GPU occupancy: the fraction of time the device is busy).\n"
"    -G       run on the GPU via OpenCL: one lane per candidate. Needs a\n"
"             fixed-width mask with -m file -H md5 (keycracking).\n"
"    -D dir   also look in 'dir' for a [:name:] dictionary's name.dict file.\n",
                    prog);
                return opt == 'h' ? 0 : 2;
        }
    }
    if (hash && !matchfile) {
        fprintf(stderr, "%s: -H needs -m with a file of digests\n", prog);
        return 2;
    }
    if (gpu && !(hash && matchfile)) {
        fprintf(stderr, "%s: -G is keycracking -- it needs -m file -H md5\n", prog);
        return 2;
    }
    if (optind != argc - 1) {
        fprintf(stderr, "usage: %s [-S] [-n | -m file [-H md5] | -d [-v]] [-j jobs] REGEX\n", prog);
        return 2;
    }
    const char *pattern = argv[optind];

    rxe_init();
    rxe_set_dict_resolver(dict_resolver);
    atexit(rxe_free_dicts);
    struct rxe *rxe = rxe_parse(pattern, 0);
    if (rxe_error(rxe) != RXE_OK) {
        fprintf(stderr, "%s: %s\n", prog, rxe_error_message(rxe));
        rxe_free(rxe);
        return 2;
    }

    struct build b;
    b.w = malloc(MAXW * sizeof *b.w);
    if (!b.w) { fprintf(stderr, "%s: out of memory\n", prog); rxe_free(rxe); return 2; }

    int nw = collect(&b, rxe);
    int ret;
    if (nw < 0) {
        fprintf(stderr, "%s: cannot compile this pattern yet -- it has %s.\n",
                prog, reason);
        ret = 1;
    } else if (b.lr_active && sink == SINK_DUP) {
        fprintf(stderr, "%s: cannot compile this pattern yet -- it has "
                "a large variable-count repeat with the dedup sink.\n", prog);
        ret = 1;
    } else {
        // The member total, baked in so the threaded count can split [0, N).
        // Left NULL when it overflows 64 bits, which keeps that count on one
        // thread -- a set that large is past enumerating whole regardless.
        mpz_t N;
        mpz_init_set_ui(N, 1);
        for (int i = 0; i < nw; i++) mpz_mul_ui(N, N, (unsigned long)b.w[i].n);
        if (b.lr_active) {
            // Fold in the repeat super-wheel's radix M = sum_{k=a}^{b} C^k, where
            // C is the members of one body copy. (b.w is only the pre/post
            // wheels; the body was lifted into lr_sw.)
            mpz_t Cz, term, M;
            mpz_init_set_ui(Cz, 1);
            for (int j = 0; j < b.lr_nsw; j++) mpz_mul_ui(Cz, Cz, (unsigned long)b.lr_sw[j].n);
            mpz_init(term); mpz_init_set_ui(M, 0);
            for (int k = b.lr_a; k <= b.lr_b; k++) {
                mpz_pow_ui(term, Cz, (unsigned long)k);
                mpz_add(M, M, term);
            }
            mpz_mul(N, N, M);
            mpz_clear(Cz); mpz_clear(term); mpz_clear(M);
        }
        char nbuf[32];
        const char *nmemb = NULL;
        if (mpz_fits_ulong_p(N)) { gmp_snprintf(nbuf, sizeof nbuf, "%Zu", N); nmemb = nbuf; }

        // The GPU path is a fixed-width mask only: a lane rebuilds its candidate
        // from its index at a constant width, no per-lane length divergence, and
        // the candidate must fit one MD5 block (< 56 bytes). Everything a
        // variable render needs -- a variable wheel, a backref, a loop repeat --
        // is declined here, so the CPU stays the answer for those.
        const char *gpu_no = NULL;
        int gpu_kind = 0;                       // 1 fixed mask, 2 loop repeat, 3 generic
        int gpu_G = 0;
        if (gpu && b.lr_active) {
            // A loop repeat runs on the GPU split by length -- but only a bare,
            // single-wheel body for now ([a-z]{1,8}); surrounding or multi-wheel
            // structure is not yet handled and stays on the CPU.
            if (b.nw != 0 || b.lr_nsw != 1 || b.has_backref)
                gpu_no = "a loop repeat with surrounding or multi-wheel structure";
            else if (b.lr_b * b.lr_sw[0].L >= 56) gpu_no = "a candidate wider than one MD5 block";
            else if (!nmemb) gpu_no = "more members than fit 64 bits";
            else gpu_kind = 2;
        } else if (gpu) {
            // A fixed mask is one grid; a pattern with structure but a fixed-class
            // tail is the generic split -- rxejit enumerates the head (backrefs
            // and all), the GPU sweeps the tail. The candidate must fit one MD5
            // block, backref copies counted.
            int anyvar = b.has_backref;             // a backref makes the render variable
            for (int i = 0; i < nw; i++) if (b.w[i].L == 0) anyvar = 1;
            int totw = gpu_maxwidth(&b);
            if (totw >= 56) gpu_no = "a candidate wider than one MD5 block";
            else if (!anyvar) {                     // a pure fixed mask: the whole
                if (!nmemb) gpu_no = "more members than fit 64 bits";   // thing is
                else { gpu_kind = 3; gpu_G = nw; }  // the low block, one empty prefix
            } else {
                // The low block: the largest fixed-class tail whose sweep is a fat
                // batch (>= ~1M) and stays a sane width, leaving a non-empty head.
                // Walked over the ops from the end, so a backref copy (OP_COPY) or
                // a group boundary ends it -- a backref that straddles into the
                // tail declines, only a head-side one is taken.
                int lowwidth = 0, expect = nw - 1; unsigned long long Plow = 1;
                for (int k = b.nops - 1; k >= 0; k--) {
                    struct op op = b.ops[k];
                    if (op.kind != OP_LAY || op.arg != expect) break;
                    struct wheel *lwh = &b.w[op.arg];
                    if (lwh->L == 0 || lowwidth + lwh->L > 40 || Plow >= (1ULL << 32)) break;
                    lowwidth += lwh->L; Plow *= (unsigned long long)lwh->n; gpu_G++; expect--;
                }
                if (gpu_G >= 1 && gpu_G < nw && Plow >= (1u << 20)) gpu_kind = 3;
                else gpu_no = "no fixed-class tail large enough for the GPU";
            }
        }

        if (gpu && gpu_no) {
            fprintf(stderr, "%s: the GPU path needs a fixed mask, a bare X{a,b}, or a "
                    "fixed-class tail -- this has %s.\n", prog, gpu_no);
            ret = 1;
        } else if (emit_only && gpu_kind == 3) { emit_gpu_generic(stdout, pattern, &b, gpu_G, psec); ret = 0; }
        else if (emit_only && gpu_kind == 2) { emit_gpu_hybrid(stdout, pattern, &b, psec); ret = 0; }
        else if (emit_only) { emit(stdout, pattern, &b, sink, nmemb, verbose, hash, psec); ret = 0; }
        else if (gpu_kind == 3) ret = compile_and_run_generic(pattern, &b, rxe, gpu_G, matchfile, psec);
        else if (gpu)       ret = compile_and_run(pattern, &b, sink, nmemb, NULL, matchfile, verbose, hash, psec, gpu_kind);
        else                ret = compile_and_run(pattern, &b, sink, nmemb, jobs, matchfile, verbose, hash, psec, 0);
        mpz_clear(N);
    }

    free_build(&b);
    free(b.w);
    rxe_free(rxe);
    return ret;
}
