/*
 * rxe_lay - decompose a finite regex-set into a positional odometer.
 *
 *          The wheel builder rxejit grew, lifted into the library so more than
 *          one back end can consume it (rxejit's C/OpenCL, jsrxe's WGSL). See
 *          rxe_lay.h for the model. The interpreter (rxe_seek/rxe_current) does
 *          the baking, so every wheel is bit-faithful to enumeration order.
 *
 *          (C) 2011 Marco "Kiko" Carnut <kiko at postcogito dot org>
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2 of the License, or (at your option) any later
 * version.  See http://www.gnu.org/licenses/gpl-2.0.html for details.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rxe.h"
#include "rxe_lay.h"

static const char *reason;         // why a pattern was declined, for the message

const char *rxe_lay_reason(void) { return reason; }

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

// The size-s block's cardinality: P(n,s) = n(n-1)..(n-s+1) ordered, or C(n,s)
// unordered. Built incrementally in __int128 (exact, since C's partial products
// stay whole), so intermediate values never wrap. Returns -1 if it exceeds 64
// bits (a choice that large cannot be one odometer digit), else 0 with *out set.
int choose_block(int n, int s, int ordered, unsigned long long *out)
{
    if (s < 0 || s > n) { *out = 0; return 0; }
    unsigned __int128 r = 1;
    for (int i = 0; i < s; i++) {
        r *= (unsigned)(n - i);
        if (!ordered) r /= (unsigned)(i + 1);        // C(n,i+1) at each step, exact
        if (r > (unsigned __int128)(~0ULL)) return -1;
    }
    *out = (unsigned long long)r;
    return 0;
}

// A combinatorial choice (re){{lo,hi!}} (ordered = permutations) or (re){{lo,hi}}
// (unordered = combinations): for each size s in [lo,hi], every choice of s of
// the pool's n members, in the interpreter's order -- the size blocks ascending,
// lexicographic (ordered) or colexicographic (unordered) within each. The pool
// re is baked as one wheel (its members are the items); the choice is a
// super-wheel like a loop repeat, with pre/post fixed structure around it.
static int add_perm(struct build *b, struct rxe_node *nd)
{
    if (b->perm_active || b->lr_active)
        { reason = "more than one combinatorial choice or large repeat"; return -1; }
    if (b->ngref)       { reason = "a combinatorial choice with a backreference"; return -1; }
    int lo = nd->rep_min, hi = nd->rep_max, ordered = nd->comb_perm;
    if (lo < 0 || hi < lo) { reason = "a combinatorial choice with an empty size range"; return -1; }

    // The pool is the whole base enumerated as one wheel -- its members are the
    // items, whether the base is an alternation (cat|dog), a class [a-z], or a
    // sequence with a separator ([:dict:] ). bake_alt does exactly this, and
    // (unlike add_rxe) does not decompose a sequence into a wheel per node.
    int w0 = b->nw, op0 = b->nops;
    if (bake_alt(b, nd->rxe)) return -1;

    struct wheel pool = b->w[w0];
    int n = pool.n;
    if (hi > n) { reason = "a choice of more members than its pool"; return -1; }

    // The super-wheel's radix is sum_{s=lo}^{hi} of the block; it is one odometer
    // digit, decoded with ULL math, so the sum must fit 64 bits.
    unsigned long long total = 0;
    for (int s = lo; s <= hi; s++) {
        unsigned long long blk;
        if (choose_block(n, s, ordered, &blk) || total > (~0ULL) - blk) {
            reason = "a combinatorial choice larger than 64 bits"; return -1;
        }
        total += blk;
    }

    b->perm_pool    = pool;
    b->perm_lo      = lo;
    b->perm_hi      = hi;
    b->perm_ordered = ordered;
    b->perm_chop    = nd->comb_chop;  // {{...?}}: quell the last item's separator
    b->perm_at      = w0;             // pre = w[0..w0); post wheels get appended here
    b->perm_active  = 1;
    b->nw           = w0;             // drop the pool wheel from the main stream,
    b->nops        = op0;            // and the LAY op that went with it
    return 0;
}

// A policy composition (A|B|...){{lo,hi!floors}}: every length lo..hi string over
// the union of the k width-1 branches with branch i appearing at least floor_i
// times, in minimal-compliance-first order. Like the permutation it is one
// super-wheel with pre/post fixed structure around it; its pool is the base
// alternation baked as one width-1 wheel (member u is union index u -- branch i
// occupies [cstart_i, cstart_i + s_i)). The back ends bake the segment table and
// unrank a member from its index; here we only capture the shape and the pool.
static int add_policy(struct build *b, struct rxe_node *nd)
{
    if (b->perm_active || b->lr_active || b->policy_active)
        { reason = "more than one combinatorial choice or large repeat"; return -1; }
    if (b->ngref) { reason = "a policy composition with a backreference"; return -1; }
    int lo = nd->rep_min, hi = nd->rep_max, k = nd->policy_nfloor;
    if (k < 1 || k > RXE_POLICY_MAXCLASS) { reason = "a policy composition with too many branches"; return -1; }

    // The pool is the whole base alternation as one wheel -- its members are the
    // branch characters in union order, exactly as branch_info / the interpreter
    // number them. Width-1 (the v1 restriction, enforced at parse), so the wheel
    // is fixed L==1 and a member is one byte PB[union index].
    int w0 = b->nw, op0 = b->nops;
    if (bake_alt(b, nd->rxe)) return -1;
    struct wheel pool = b->w[w0];
    if (pool.L != 1) { reason = "a policy composition over multi-character branches"; return -1; }

    // Per-branch sizes s_i and their start offsets in the union (a prefix sum) --
    // the segment machinery and the character unrank need both.
    int t = 0;
    unsigned long acc = 0;
    for (struct rxe_alt *a = nd->rxe->head; a && t < k; a = a->next, t++) {
        if (!mpz_fits_ulong_p(a->nitems)) { reason = "a policy branch too large to unroll"; return -1; }
        b->policy_s[t]      = mpz_get_ui(a->nitems);
        b->policy_cstart[t] = acc;
        acc += b->policy_s[t];
    }
    if (t != k) { reason = "a policy composition whose branch count changed"; return -1; }

    b->policy_pool   = pool;
    b->policy_lo     = lo;
    b->policy_hi     = hi;
    b->policy_k      = k;
    b->policy_soaker = nd->policy_soaker;   // -1 => back end defaults to the last
    for (int i = 0; i < k; i++) b->policy_floor[i] = nd->policy_floor[i];
    b->policy_at     = w0;
    b->policy_active = 1;
    b->nw            = w0;                   // drop the pool wheel from the stream,
    b->nops          = op0;                  // and the LAY op that went with it
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

    if (nd->is_policy)
        return add_policy(b, nd);

    if (nd->is_comb)
        return add_perm(b, nd);

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
        !nd->is_dict && !nd->is_backref && !nd->is_inf && !nd->is_policy)
        return add_rxe(b, nd->rxe);

    reason = nd->is_inf     ? "an unbounded repeat"
           : nd->is_dict    ? "a dictionary"
           : nd->is_backref ? "a backreference"
           : nd->is_comb    ? "a combination"
           : nd->is_policy  ? "a policy composition"
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
int rxe_lay_build(struct build *b, struct rxe *rxe)
{
    b->nw = 0; b->bake = NULL; b->nbake = 0; b->cbake = 0; b->root = rxe;
    b->ops = NULL; b->nops = 0; b->cops = 0;
    b->gref = NULL; b->ngref = 0; b->grxe = NULL; b->ngroup = 0; b->has_backref = 0;
    b->lr_active = 0; b->perm_active = 0; b->policy_active = 0;
    b->w = malloc(MAXW * sizeof *b->w);
    if (!b->w) { reason = "out of memory"; return -1; }
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

void rxe_lay_free(struct build *b)
{
    for (int i = 0; i < b->nbake; i++) free(b->bake[i]);
    free(b->bake); free(b->ops); free(b->gref); free(b->grxe); free(b->w);
}

