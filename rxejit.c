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
 *          group is laid. So masks, alternations even and uneven, subroutines,
 *          bounded repeats, dictionaries, and backreferences all compile --
 *          every finite pattern. Only an unbounded (infinite) repeat, or a set
 *          too large to unroll, declines by name, and the interpreter stays the
 *          answer there. It runs the compiled program (or prints the C with -S)
 *          under a chosen sink: write the members, count them, match them
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

#define MAXW 4096                  // most positions an unrolled mask may have

// What the generated loop does with each member. write is the default -- the
// members to stdout, as rxenum -e does; count only tallies them, which times
// the enumeration with no I/O in the way; match probes each against a target
// set loaded at runtime and prints the hits (a mask being a keyspace to sift);
// dup hashes each into a per-thread set and reports the repeats, merged at the
// join -- meaningful now that alternations put duplicates in the set.
enum { SINK_WRITE, SINK_COUNT, SINK_MATCH, SINK_DUP };

#define ALT_CAP 65536              // most members a baked alternation may hold

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
    // an unbounded one is shortlex), but its members vary in width. Re-parse its
    // own source span into a standalone expression and bake that as one variable
    // wheel -- the same treatment an uneven alternation gets. Too many members
    // to unroll, and bake_alt declines it, as it would a huge alternation.
    if (nd->is_repeat && !nd->is_inf && nd->rep_max != RXE_REP_UNBOUNDED && nd->rxe) {
        int len = nd->src_end - nd->src_start;
        if (len <= 0 || !b->root->source) { reason = "a variable-count repeat"; return -1; }
        char *sub = malloc((size_t)len + 1);
        if (!sub) { reason = "out of memory"; return -1; }
        memcpy(sub, b->root->source + nd->src_start, (size_t)len);
        sub[len] = 0;
        struct rxe *sr = rxe_parse(sub, 0);
        free(sub);
        if (rxe_error(sr) != RXE_OK) { rxe_free(sr); reason = "a variable-count repeat"; return -1; }
        int rc = bake_alt(b, sr);
        rxe_free(sr);
        return rc;
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
    if (find_refs(b, rxe)) return -1;
    return add_rxe(b, rxe) ? -1 : b->nw;
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
                 int sink, const char *nmemb, int verbose, int hash)
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

    // Sizing. A member is rebuilt each step (not delta-patched) when a wheel is
    // variable-width, or a backreference copies a group -- either makes offsets
    // depend on the choice. bufcap is the most a member can hold; multi marks
    // memcpy (and string.h). Backref patterns cost bufcap the copied spans too,
    // so it is walked over the op list rather than the wheels.
    int variable = B->has_backref, multi = B->has_backref;
    for (int i = 0; i < nw; i++)
        if (w[i].L == 0) { variable = 1; multi = 1; }
        else if (w[i].L > 1) multi = 1;

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
    fputc('\n', o);

    if (rt) fputs(RXEJIT_RT, o), fputc('\n', o);
    if (match) {
        fputs("static struct rt_set TB;   /* the targets, read-only once loaded */\n", o);
        fputs("static pthread_mutex_t MX = PTHREAD_MUTEX_INITIALIZER;\n\n", o);
    }

    fputs(dup
        ? "static void run(unsigned long long from, unsigned long long count, struct rt_dup *d)\n{\n"
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

    fprintf(o, "    unsigned char buf[%d];\n", bufcap + 1);
    if (!variable) fprintf(o, "    buf[%d] = '\\n';\n", TL);

    // Seed each wheel from 'from': digit = from %% radix, then from /= radix,
    // walking from the least significant wheel up, so the walk starts at 'from'.
    fputs("    unsigned long long f = from;\n", o);
    for (int i = nw - 1; i >= 0; i--)
        fprintf(o, "    int i%d = f %% %d; f /= %d;\n", i, w[i].n, w[i].n);
    if (!variable)                                  // fixed: lay the initial member once
        for (int i = 0; i < nw; i++) {
            char e[16]; snprintf(e, sizeof e, "i%d", i);
            fputs("    ", o); emit_lay(o, i, off[i], w[i].L, e); fputc('\n', o);
        }

    // The member length reaching the sink: a compile-time constant when fixed,
    // the running length 'p' when variable (rebuilt at the top of the loop).
    char len[16], lenp1[16];
    if (variable) { strcpy(len, "p"); strcpy(lenp1, "p + 1"); }
    else { snprintf(len, sizeof len, "%d", TL); snprintf(lenp1, sizeof lenp1, "%d", TL + 1); }

    if (acc) fputs("    unsigned long long n = 0;\n", o);
    fputs("    unsigned long long done = 0;\n", o);
    fputs("    for (;;) {\n", o);
    if (variable) {
        // Rebuild the member: walk the op list, laying each wheel's current
        // branch and copying any backreferenced group's bytes, tracking the
        // running length p (a variable wheel or a copy shifts everything after).
        //
        // TODO(perf): this rebuilds the whole member every step (a memcpy per
        // wheel), ~7-10x slower than the fixed delta path. Most steps only turn
        // the last wheel, so re-laying just the suffix from the wheel that
        // carried -- tracking each wheel's current offset -- would collapse the
        // common case back toward fixed speed. Left out of the first correct
        // version; worth it only if a variable-length workload is throughput-bound.
        for (int g = 0; g < B->ngroup; g++)
            fprintf(o, "        int g%d_pos = 0, g%d_len = 0;\n", g, g);
        fputs("        int p = 0;\n", o);
        for (int k = 0; k < B->nops; k++) {
            struct op op = B->ops[k];
            int i = op.arg;
            if (op.kind == OP_LAY) {
                if (w[i].L)
                    fprintf(o, "        memcpy(buf + p, A%d + i%d * %d, %d); p += %d;\n",
                            i, i, w[i].L, w[i].L, w[i].L);
                else
                    fprintf(o, "        memcpy(buf + p, A%d + A%do[i%d], A%dl[i%d]);"
                               " p += A%dl[i%d];\n", i, i, i, i, i, i, i);
            } else if (op.kind == OP_OPEN) {
                fprintf(o, "        g%d_pos = p;\n", i);
            } else if (op.kind == OP_CLOSE) {
                fprintf(o, "        g%d_len = p - g%d_pos;\n", i, i);
            } else {  // OP_COPY
                fprintf(o, "        memcpy(buf + p, buf + g%d_pos, g%d_len); p += g%d_len;\n",
                        i, i, i);
            }
        }
        fputs("        buf[p] = '\\n';\n", o);
    }
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
    fputs("        if (count && ++done == count) break;\n", o);
    if (variable) {
        // Advance the odometer without touching the buffer; it is rebuilt above.
        fputs("        {\n            int c = 1;\n", o);
        for (int i = nw - 1; i >= 0; i--)
            fprintf(o, "            if (c) { if (++i%d < %d) c = 0; else i%d = 0; }\n",
                    i, w[i].n, i);
        fputs("            if (c) break;\n        }\n", o);
    } else {
        for (int i = nw - 1; i >= 0; i--) {
            char e[16]; snprintf(e, sizeof e, "i%d", i);
            fprintf(o, "        if (++i%d < %d) { ", i, w[i].n);
            emit_lay(o, i, off[i], w[i].L, e);
            fprintf(o, " continue; } i%d = 0; ", i);
            emit_lay(o, i, off[i], w[i].L, "0");
            fputc('\n', o);
        }
        fputs("        break;\n", o);
    }
    fputs("    }\n", o);
    if (acc) fputs("    *acc += n;\n", o);
    fputs("}\n\n", o);

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
        fprintf(o, "#define NMEMB %sULL\n#define MAXT  256\n\n", nmemb);
        fputs("struct shard { unsigned long long from, count, total; };\n\n"
              "static void *worker(void *p)\n{\n"
              "    struct shard *s = p;\n"
              "    s->total = 0;\n"
              "    run(s->from, s->count, &s->total);\n"
              "    return 0;\n"
              "}\n\n"
              "int main(int argc, char **argv)\n{\n", o);
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
              "        sh[t].count = base + ((unsigned long long)t < rem ? 1 : 0);\n"
              "        off += sh[t].count;\n"
              "    }\n"
              "    for (int t = 1; t < T; t++) pthread_create(&tid[t], 0, worker, &sh[t]);\n"
              "    worker(&sh[0]);\n"
              "    for (int t = 1; t < T; t++) pthread_join(tid[t], 0);\n"
              "    unsigned long long total = 0;\n"
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
                           const char *matchfile, int verbose, int hash)
{
    char dir[] = "/tmp/rxejit.XXXXXX";
    if (!mkdtemp(dir)) { perror("rxejit: mkdtemp"); return 2; }

    char src[64], exe[64];
    snprintf(src, sizeof src, "%s/m.c", dir);
    snprintf(exe, sizeof exe, "%s/m", dir);

    int ret = 0;
    FILE *f = fopen(src, "w");
    if (!f) { perror("rxejit: fopen"); ret = 2; goto done; }
    emit(f, pattern, B, sink, nmemb, verbose, hash);
    fclose(f);

    const char *cc = getenv("CC");
    if (!cc || !*cc) cc = "cc";
    char *cargv[] = { (char *)cc, "-O2", "-pthread", src, "-o", exe, NULL };
    int rc = spawn(cargv);
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
    int emit_only = 0, sink = SINK_WRITE, verbose = 0, hash = 0, opt;
    const char *jobs = NULL;              // thread count, forwarded to the exe
    const char *matchfile = NULL;         // target file for -m

    while ((opt = getopt(argc, argv, "Sndvj:m:H:D:h")) != -1) {
        switch (opt) {
            case 'S': emit_only = 1; break;
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
"  Handles masks, alternations, and bounded repeats -- any finite pattern short\n"
"  of a dictionary or backreference, which are declined with a reason.\n"
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
"    -D dir   also look in 'dir' for a [:name:] dictionary's name.dict file.\n",
                    prog);
                return opt == 'h' ? 0 : 2;
        }
    }
    if (hash && !matchfile) {
        fprintf(stderr, "%s: -H needs -m with a file of digests\n", prog);
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
    } else {
        // The member total, baked in so the threaded count can split [0, N).
        // Left NULL when it overflows 64 bits, which keeps that count on one
        // thread -- a set that large is past enumerating whole regardless.
        mpz_t N;
        mpz_init_set_ui(N, 1);
        for (int i = 0; i < nw; i++) mpz_mul_ui(N, N, (unsigned long)b.w[i].n);
        char nbuf[32];
        const char *nmemb = NULL;
        if (mpz_fits_ulong_p(N)) { gmp_snprintf(nbuf, sizeof nbuf, "%Zu", N); nmemb = nbuf; }

        if (emit_only) { emit(stdout, pattern, &b, sink, nmemb, verbose, hash); ret = 0; }
        else           ret = compile_and_run(pattern, &b, sink, nmemb, jobs, matchfile, verbose, hash);
        mpz_clear(N);
    }

    free_build(&b);
    free(b.w);
    rxe_free(rxe);
    return ret;
}
