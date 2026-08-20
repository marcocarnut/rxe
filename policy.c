/*
 * librxe - a library for enumerating sets described by regexes, version 1.1.0
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

// Policy composition: '(A|B|...|K){{n,m!x1,...,xk}}' is every string of length
// n..m over the disjoint union of the k branches in which branch i occurs at
// least xi times -- the shape of a password composition policy, which a plain
// regex can only express as a lookahead or a combinatorial blow-up.
//
// The set has a closed-form bijection with the integers, so the library's
// index<->member contract holds. An index decodes in three nested steps:
//   1. the length L      -- subtract each length's count (a dynamic program);
//   2. the count-vector  -- how many of each class, walked in the minimal-
//      compliance-first order (the surplus pooled in the soaker branch leads);
//   3. within it, the arrangement (which position is which class, a multiset
//      permutation) and the characters (a mixed radix over the classes).
// The member is stored as one union-index per position in rep_digit[], the same
// place a repetition or combination keeps its indices, and rendered the same
// way: the base alternation is seeked to each and its character taken.

#include "rxe.h"
#include "policy.h"
#include "repeat.h"

/* --------------------------- small helpers ------------------------------- */

static int floor_sum(const int *floors, int k)
{
    int s = 0;
    for (int i = 0; i < k; i++) s += floors[i] < 0 ? 0 : floors[i];
    return s;
}

// multinomial(total; counts[0..k-1]) = total! / prod counts_i!  (counts are ints)
static void multinom(mpz_t out, int total, const int *counts, int k)
{
    mpz_fac_ui(out, (unsigned long)total);
    mpz_t f;
    mpz_init(f);
    for (int i = 0; i < k; i++) {
        mpz_fac_ui(f, (unsigned long)counts[i]);
        mpz_divexact(out, out, f);
    }
    mpz_clear(f);
}

// The number of members with count-vector cv: multinomial(L;cv) * prod s_i^{cv_i}.
static void seg_size(mpz_t out, int L, const int *cv, mpz_t *s, int k)
{
    multinom(out, L, cv, k);
    mpz_t p;
    mpz_init(p);
    for (int i = 0; i < k; i++) {
        mpz_pow_ui(p, s[i], (unsigned long)cv[i]);
        mpz_mul(out, out, p);
    }
    mpz_clear(p);
}

// The per-branch cardinalities s_i and their start offsets in the base
// alternation's union index space. alt->start is exactly the offset the
// alternation's own seek uses, so seeking the base to start_i + c lands on
// branch i's c-th character. Each is mpz-initialised here; cleared by the caller.
static void branch_info(struct rxe *base, mpz_t *s, mpz_t *start, int k)
{
    int t = 0;
    for (struct rxe_alt *a = base->head; a && t < k; a = a->next, t++) {
        mpz_init_set(s[t],     a->nitems);
        mpz_init_set(start[t], a->start);
    }
}

/* --------------------------- Counting ----------------------------------- */

// dp[j] = number of length-j strings over the classes folded in so far, each
// meeting its floor. Folding in class t of size s_t and floor f_t:
//   dp'[j] = sum_{n=f_t..j} C(j,n) * s_t^n * dp[j-n]
// After all k classes, dp[L] is the count at length L. Fills dp[0..hi], which
// the caller has mpz-initialised.
static void policy_dp(struct rxe *base, int hi, const int *floors, int k, mpz_t *dp)
{
    mpz_t *s = NEW(k, mpz_t);
    { int t = 0;
      for (struct rxe_alt *a = base->head; a && t < k; a = a->next, t++)
          mpz_init_set(s[t], a->nitems); }
    mpz_t *cur = NEW(hi + 1, mpz_t), *nxt = NEW(hi + 1, mpz_t);
    for (int j = 0; j <= hi; j++) { mpz_init(cur[j]); mpz_init(nxt[j]); }
    mpz_set_ui(cur[0], 1);

    mpz_t term, sp, binom;
    mpz_init(term); mpz_init(sp); mpz_init(binom);
    for (int t = 0; t < k; t++) {
        int ft = floors[t] < 0 ? 0 : floors[t];
        for (int j = 0; j <= hi; j++) {
            mpz_set_ui(nxt[j], 0);
            if (ft > j) continue;
            mpz_bin_uiui(binom, (unsigned long)j, (unsigned long)ft);
            mpz_pow_ui(sp, s[t], (unsigned long)ft);
            for (int n = ft; n <= j; n++) {
                mpz_mul(term, binom, sp);
                mpz_mul(term, term, cur[j - n]);
                mpz_add(nxt[j], nxt[j], term);
                if (n < j) {
                    mpz_mul_ui(binom, binom, (unsigned long)(j - n));
                    mpz_divexact_ui(binom, binom, (unsigned long)(n + 1));
                    mpz_mul(sp, sp, s[t]);
                }
            }
        }
        mpz_t *sw = cur; cur = nxt; nxt = sw;
    }
    for (int j = 0; j <= hi; j++) mpz_set(dp[j], cur[j]);

    mpz_clear(term); mpz_clear(sp); mpz_clear(binom);
    for (int j = 0; j <= hi; j++) { mpz_clear(cur[j]); mpz_clear(nxt[j]); }
    rxe_mem_free(cur); rxe_mem_free(nxt);
    for (int t = 0; t < k; t++) mpz_clear(s[t]);
    rxe_mem_free(s);
}

void rxe_policy_nitems(mpz_t out, struct rxe *base, int lo, int hi,
                       const int *floors, int k)
{
    mpz_set_ui(out, 0);
    if (hi < lo || lo < 0 || k <= 0) return;
    mpz_t *dp = NEW(hi + 1, mpz_t);
    for (int j = 0; j <= hi; j++) mpz_init(dp[j]);
    policy_dp(base, hi, floors, k, dp);
    for (int L = lo; L <= hi; L++) mpz_add(out, out, dp[L]);
    for (int j = 0; j <= hi; j++) mpz_clear(dp[j]);
    rxe_mem_free(dp);
}

/* --------------------------- Segments (for the back ends) --------------- */

// The code generators (rxejit's C/OpenCL, jsrxe's WGSL) decode a policy member
// from a 64-bit index over a baked table of segments -- one per (length,
// count-vector) block, in the same minimal-compliance-first order the
// interpreter walks. This lays that table out for them: seg_L[i], the count
// vector seg_cv[i*k + t], and the cumulative offset seg_off[i] (members before
// segment i); seg_off[nseg] is the grand total. 's' holds the k branch
// cardinalities. Returns the segment count, or -1 (with *why set) if the total
// would exceed 64 bits -- past what a u64 odometer digit can address -- or if
// there are more than 'cap' segments. The walk mirrors pdec_walk exactly, so a
// generated candidate at an index is the interpreter's member at it.
// Whether an mpz fits an unsigned 64-bit int, and its value as one -- independent
// of the platform's 'unsigned long' width (32 bits under emscripten/WASM, 64 on a
// 64-bit host), which mpz_fits_ulong_p / mpz_get_ui follow. The segment offsets
// run to 64 bits on any host, so the code generators need the full width there.
static int mpz_fits_u64(const mpz_t z)
{
    return mpz_sgn(z) >= 0 && mpz_sizeinbase(z, 2) <= 64;
}
static unsigned long long mpz_get_u64(const mpz_t z)
{
    unsigned char buf[8] = {0};
    size_t count = 0;
    mpz_export(buf, &count, -1, 1, 0, 0, z);      // least-significant byte first
    unsigned long long v = 0;
    for (size_t i = 0; i < count && i < 8; i++) v |= (unsigned long long)buf[i] << (8 * i);
    return v;
}

struct segw {
    int k, L, soaker, f, m, cap, nseg, err;
    const int *floors, *ns;
    mpz_t *s;
    int *ext, *cv;
    mpz_t total, seg;
    int *seg_L, *seg_cv;
    unsigned long long *seg_off;
    const char *why;
};

static void segw_emit(struct segw *w)
{
    if (w->err) return;
    int k = w->k, nssum = 0;
    for (int i = 0; i < k; i++) if (i != w->soaker) nssum += w->ext[i];
    w->ext[w->soaker] = w->f - nssum;
    for (int i = 0; i < k; i++)
        w->cv[i] = (w->floors[i] < 0 ? 0 : w->floors[i]) + w->ext[i];
    seg_size(w->seg, w->L, w->cv, w->s, k);
    if (!mpz_fits_u64(w->seg) || !mpz_fits_u64(w->total)) {
        w->err = 1; w->why = "more members than fit 64 bits"; return;
    }
    if (w->nseg >= w->cap) { w->err = 1; w->why = "too many policy segments to bake"; return; }
    w->seg_L[w->nseg] = w->L;
    for (int i = 0; i < k; i++) w->seg_cv[w->nseg * k + i] = w->cv[i];
    w->seg_off[w->nseg] = mpz_get_u64(w->total);
    w->nseg++;
    mpz_add(w->total, w->total, w->seg);
    if (!mpz_fits_u64(w->total)) { w->err = 1; w->why = "more members than fit 64 bits"; }
}

static void segw_walk(struct segw *w, int idx, int rem)
{
    if (w->err) return;
    if (w->m == 0)         { segw_emit(w); return; }
    if (idx == w->m - 1)   { w->ext[w->ns[idx]] = rem; segw_emit(w); return; }
    for (int v = 0; v <= rem && !w->err; v++) {
        w->ext[w->ns[idx]] = v;
        segw_walk(w, idx + 1, rem - v);
    }
}

int rxe_policy_segments(const unsigned long *s_ul, int k, int lo, int hi,
                        const int *floors, int soaker0, int cap,
                        int *seg_L, int *seg_cv, unsigned long long *seg_off,
                        const char **why)
{
    if (why) *why = NULL;
    int soaker = soaker0 >= 0 ? soaker0 : k - 1;
    struct segw w;
    w.k = k; w.soaker = soaker; w.cap = cap; w.nseg = 0; w.err = 0; w.why = NULL;
    w.floors = floors; w.seg_L = seg_L; w.seg_cv = seg_cv; w.seg_off = seg_off;
    w.s = NEW(k, mpz_t);
    for (int i = 0; i < k; i++) mpz_init_set_ui(w.s[i], s_ul[i]);
    w.ext = NEW(k, int); w.cv = NEW(k, int);
    w.ns = NULL;
    int *ns = NEW(k > 0 ? k : 1, int), m = 0;
    for (int i = 0; i < k; i++) if (i != soaker) ns[m++] = i;
    w.ns = ns; w.m = m;
    mpz_init_set_ui(w.total, 0);
    mpz_init(w.seg);

    int fsum = floor_sum(floors, k);
    for (int L = lo; L <= hi && !w.err; L++) {
        int f = L - fsum;
        if (f < 0) continue;
        w.L = L; w.f = f;
        for (int d = 0; d <= f && !w.err; d++) {
            if (m == 0 && d > 0) break;      // one class: a single vector per length
            segw_walk(&w, 0, d);
        }
    }
    if (!w.err) seg_off[w.nseg] = mpz_get_u64(w.total);   // grand total

    int rc = w.err ? -1 : w.nseg;
    if (w.err && why) *why = w.why;
    for (int i = 0; i < k; i++) mpz_clear(w.s[i]);
    rxe_mem_free(w.s); rxe_mem_free(w.ext); rxe_mem_free(w.cv); rxe_mem_free(ns);
    mpz_clear(w.total); mpz_clear(w.seg);
    return rc;
}

/* --------------------------- Decoding ----------------------------------- */

// State threaded through the count-vector walk, which serves both directions.
// Decode (target == NULL): 'j' is the remaining index; each skipped segment is
// subtracted, and the segment it lands in is kept in 'cv'. Rank (target set):
// the sizes of the segments strictly before 'target' in the walk order are
// accumulated into 'acc', stopping at target -- the offset of target's block.
struct pdec {
    int k, L, soaker, f;
    mpz_t *s;                 // branch cardinalities
    const int *floors;
    mpz_t j;                  // decode: remaining index
    mpz_t acc;                // rank: sum of sizes before the target
    const int *target;        // rank: the count-vector whose offset we want
    int *ext;                 // scratch: per-branch surplus above the floor
    int *cv;                  // decode output: the found count-vector
    int found;
};

// Consider one fully-assigned count-vector in walk order.
static int pdec_take(struct pdec *c)
{
    int k = c->k, nssum = 0;
    for (int i = 0; i < k; i++) if (i != c->soaker) nssum += c->ext[i];
    c->ext[c->soaker] = c->f - nssum;                 // the soaker takes the rest
    int *cv = c->cv;
    for (int i = 0; i < k; i++) cv[i] = (c->floors[i] < 0 ? 0 : c->floors[i]) + c->ext[i];
    mpz_t seg;
    mpz_init(seg);
    seg_size(seg, c->L, cv, c->s, k);
    int hit;
    if (c->target) {                                  // rank: stop at the target
        hit = 1;
        for (int i = 0; i < k; i++) if (cv[i] != c->target[i]) { hit = 0; break; }
        if (hit) c->found = 1;
        else     mpz_add(c->acc, c->acc, seg);
    } else {                                           // decode: stop where j lands
        hit = mpz_cmp(c->j, seg) < 0;
        if (hit) c->found = 1;
        else     mpz_sub(c->j, c->j, seg);
    }
    mpz_clear(seg);
    return hit;
}

// Walk the non-soaker branches ns[idx..m-1], assigning each a surplus so they
// sum to 'rem', in lexicographic (minimal-first) order; the soaker absorbs the
// remainder in pdec_take. Returns 1 once a segment is kept.
static int pdec_walk(struct pdec *c, const int *ns, int m, int idx, int rem)
{
    if (m == 0)       return pdec_take(c);            // only the soaker exists
    if (idx == m - 1) { c->ext[ns[idx]] = rem; return pdec_take(c); }
    for (int v = 0; v <= rem; v++) {                  // lex: this branch 0 upward
        c->ext[ns[idx]] = v;
        if (pdec_walk(c, ns, m, idx + 1, rem - v)) return 1;
    }
    return 0;
}

// Decode the member at linear index 'pos' into node->rep_digit[0..L-1], each a
// union index into the base alternation. Returns 1 when pos is past the end.
static int policy_decode(struct rxe_node *node, const mpz_t pos)
{
    if (mpz_sgn(pos) < 0 || mpz_cmp(pos, node->nitems) >= 0) return 1;

    int k = node->policy_nfloor;
    int lo = node->rep_min, hi = node->rep_max;
    int soaker = node->policy_soaker >= 0 ? node->policy_soaker : k - 1;

    mpz_t *s = NEW(k, mpz_t), *start = NEW(k, mpz_t);
    branch_info(node->rxe, s, start, k);

    // 1. the length: subtract each length's count until the index fits.
    mpz_t *dp = NEW(hi + 1, mpz_t);
    for (int j = 0; j <= hi; j++) mpz_init(dp[j]);
    policy_dp(node->rxe, hi, node->policy_floor, k, dp);
    mpz_t j;
    mpz_init_set(j, pos);
    int L = lo;
    for (; L <= hi; L++) { if (mpz_cmp(j, dp[L]) < 0) break; mpz_sub(j, j, dp[L]); }
    for (int q = 0; q <= hi; q++) mpz_clear(dp[q]);
    rxe_mem_free(dp);

    // 2. the count-vector, in minimal-compliance-first order.
    int *ns = NEW(k > 0 ? k : 1, int), m = 0;
    for (int i = 0; i < k; i++) if (i != soaker) ns[m++] = i;
    struct pdec c;
    c.k = k; c.L = L; c.soaker = soaker; c.f = L - floor_sum(node->policy_floor, k);
    c.s = s; c.floors = node->policy_floor; c.found = 0; c.target = NULL;
    c.ext = NEW(k, int); c.cv = NEW(k, int);
    mpz_init_set(c.j, j);
    mpz_init(c.acc);
    for (int d = 0; d <= c.f && !c.found; d++) pdec_walk(&c, ns, m, 0, d);
    mpz_clear(j); mpz_clear(c.acc);

    // 3. within the count-vector: arrangement (multiset permutation) and chars.
    int rc = 1;
    if (c.found && rxe_repeat_reserve(node, L) == 0) {
        node->rep_count = L;
        mpz_t char_size, arr, chr;
        mpz_init(char_size); mpz_init(arr); mpz_init(chr);
        mpz_set_ui(char_size, 1);
        { mpz_t p; mpz_init(p);
          for (int i = 0; i < k; i++) { mpz_pow_ui(p, s[i], (unsigned long)c.cv[i]); mpz_mul(char_size, char_size, p); }
          mpz_clear(p); }
        mpz_tdiv_qr(arr, chr, c.j, char_size);        // arrangement rank / char rank

        // multiset-permutation unrank of 'arr' into the class of each position.
        int *pos_cls = NEW(L > 0 ? L : 1, int);
        int *rem = NEW(k, int);
        for (int i = 0; i < k; i++) rem[i] = c.cv[i];
        mpz_t ways;
        mpz_init(ways);
        for (int p = 0; p < L; p++) {
            for (int t = 0; t < k; t++) {
                if (rem[t] == 0) continue;
                rem[t]--;
                multinom(ways, L - p - 1, rem, k);
                if (mpz_cmp(arr, ways) < 0) { pos_cls[p] = t; break; }
                mpz_sub(arr, arr, ways);
                rem[t]++;
            }
        }
        mpz_clear(ways);

        // char unrank: mixed radix, last position least significant. Each
        // position's union index is its class's start plus the chosen character.
        mpz_t cidx;
        mpz_init(cidx);
        for (int p = L - 1; p >= 0; p--) {
            mpz_tdiv_qr(chr, cidx, chr, s[pos_cls[p]]);   // chr /= s, cidx = old chr mod s
            mpz_add(node->rep_digit[p], start[pos_cls[p]], cidx);
        }
        mpz_clear(cidx);

        rxe_mem_free(pos_cls); rxe_mem_free(rem);
        mpz_clear(char_size); mpz_clear(arr); mpz_clear(chr);
        rc = 0;
    }

    mpz_clear(c.j);
    rxe_mem_free(c.ext); rxe_mem_free(c.cv); rxe_mem_free(ns);
    for (int i = 0; i < k; i++) { mpz_clear(s[i]); mpz_clear(start[i]); }
    rxe_mem_free(s); rxe_mem_free(start);
    return rc;
}

// The local index of a member from its decomposition: the class of each
// position (cls[p], a branch index) and the character chosen within it
// (cidx[p]). Exact inverse of policy_decode -- shorter lengths, then the
// count-vectors before this one in the minimal-first walk, then the arrangement
// (a multiset-permutation rank) and the characters (a mixed radix).
void rxe_policy_local(struct rxe_node *node, const int *cls, const int *cidx,
                      int L, mpz_t out)
{
    int k = node->policy_nfloor;
    int lo = node->rep_min, hi = node->rep_max;
    int soaker = node->policy_soaker >= 0 ? node->policy_soaker : k - 1;

    mpz_t *s = NEW(k, mpz_t), *start = NEW(k, mpz_t);
    branch_info(node->rxe, s, start, k);

    int *cv = NEW(k, int);
    for (int i = 0; i < k; i++) cv[i] = 0;
    for (int p = 0; p < L; p++) cv[cls[p]]++;

    // 1. shorter lengths, all laid before this one.
    mpz_t *dp = NEW(hi + 1, mpz_t);
    for (int j = 0; j <= hi; j++) mpz_init(dp[j]);
    policy_dp(node->rxe, hi, node->policy_floor, k, dp);
    mpz_set_ui(out, 0);
    for (int Lp = lo; Lp < L; Lp++) mpz_add(out, out, dp[Lp]);
    for (int j = 0; j <= hi; j++) mpz_clear(dp[j]);
    rxe_mem_free(dp);

    // 2. the count-vectors laid before this one in minimal-first order.
    int *ns = NEW(k > 0 ? k : 1, int), m = 0;
    for (int i = 0; i < k; i++) if (i != soaker) ns[m++] = i;
    struct pdec c;
    c.k = k; c.L = L; c.soaker = soaker; c.f = L - floor_sum(node->policy_floor, k);
    c.s = s; c.floors = node->policy_floor; c.found = 0; c.target = cv;
    c.ext = NEW(k, int); c.cv = NEW(k, int);
    mpz_init_set_ui(c.j, 0);
    mpz_init_set_ui(c.acc, 0);
    for (int d = 0; d <= c.f && !c.found; d++) pdec_walk(&c, ns, m, 0, d);
    mpz_add(out, out, c.acc);
    mpz_clear(c.j); mpz_clear(c.acc);
    rxe_mem_free(c.ext); rxe_mem_free(c.cv); rxe_mem_free(ns);

    // 3. within the count-vector: the arrangement rank * char_size + char rank.
    mpz_t char_size;
    mpz_init_set_ui(char_size, 1);
    { mpz_t p; mpz_init(p);
      for (int i = 0; i < k; i++) { mpz_pow_ui(p, s[i], (unsigned long)cv[i]); mpz_mul(char_size, char_size, p); }
      mpz_clear(p); }

    mpz_t arr;
    mpz_init_set_ui(arr, 0);
    { int *rem = NEW(k, int); for (int i = 0; i < k; i++) rem[i] = cv[i];
      mpz_t ways; mpz_init(ways);
      for (int p = 0; p < L; p++) {
          int t = cls[p];
          for (int u = 0; u < t; u++) {
              if (rem[u] == 0) continue;
              rem[u]--; multinom(ways, L - p - 1, rem, k); mpz_add(arr, arr, ways); rem[u]++;
          }
          rem[t]--;
      }
      mpz_clear(ways); rxe_mem_free(rem); }

    mpz_t chr;
    mpz_init_set_ui(chr, 0);
    for (int p = 0; p < L; p++) { mpz_mul(chr, chr, s[cls[p]]); mpz_add_ui(chr, chr, (unsigned long)cidx[p]); }

    mpz_t tmp;
    mpz_init(tmp);
    mpz_mul(tmp, arr, char_size);
    mpz_add(out, out, tmp);
    mpz_add(out, out, chr);
    mpz_clear(tmp); mpz_clear(arr); mpz_clear(chr); mpz_clear(char_size);

    for (int i = 0; i < k; i++) { mpz_clear(s[i]); mpz_clear(start[i]); }
    rxe_mem_free(s); rxe_mem_free(start); rxe_mem_free(cv);
}

/* --------------------------- Public API --------------------------------- */

void rxe_policy_make(struct rxe_node *node, int lo, int hi,
                     const int *floors, int k, int soaker)
{
    node->is_policy     = 1;
    node->rep_min       = lo;
    node->rep_max       = hi;
    node->rep_count     = 0;
    node->rep_digit     = NULL;
    node->rep_len       = NULL;
    node->rep_alloc     = 0;
    node->is_inf        = 0;
    node->policy_nfloor = k;
    node->policy_soaker = soaker;
    node->policy_floor  = NEW(k, int);
    for (int i = 0; i < k; i++) node->policy_floor[i] = floors[i];
    mpz_set_ui(node->comb_index, 0);
    rxe_policy_nitems(node->nitems, node->rxe, lo, hi, floors, k);
    if (mpz_sgn(node->nitems) > 0) {
        mpz_t z;
        mpz_init_set_ui(z, 0);
        policy_decode(node, z);
        mpz_clear(z);
    }
}

int rxe_policy_seek(struct rxe_node *node, const mpz_t pos)
{
    if (policy_decode(node, pos)) return 1;
    mpz_set(node->comb_index, pos);
    return 0;
}

int rxe_policy_iterate(struct rxe_node *node)
{
    mpz_t next;
    int carry = 0;
    mpz_init(next);
    mpz_add_ui(next, node->comb_index, 1);
    if (mpz_cmp(next, node->nitems) >= 0) { mpz_set_ui(next, 0); carry = 1; }
    policy_decode(node, next);
    mpz_set(node->comb_index, next);
    mpz_clear(next);
    return carry;
}
