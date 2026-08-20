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
// least xi times -- the shape of a password composition policy ("8-16 chars,
// at least one of each of lower/upper/digit/punct"), which a plain regex can
// only express as a lookahead or a combinatorial blow-up of alternatives.
//
// The point, as everywhere in the library, is a closed-form count: the number
// of length-L members is the sum over count-vectors (n_1..n_k, n_i >= x_i,
// sum n_i = L) of multinomial(L; n) * product s_i^{n_i}, where s_i is branch
// i's cardinality. That sum has a clean dynamic program -- add one class at a
// time, folding its contribution into a running per-length tally -- so no
// count-vector is ever walked. This file is that count and the node setup;
// the unrank/rank that make the members walkable land in slice 2.

#include "rxe.h"
#include "policy.h"
#include "repeat.h"

// The per-branch cardinalities s_1..s_k, read off the base alternation's
// branches (one branch = one class = one alternation of the base). The caller
// guarantees there are exactly k of them. Each s_i is mpz-initialised here and
// cleared by the caller.
static void branch_sizes(struct rxe *base, mpz_t *s, int k)
{
    int i = 0;
    for (struct rxe_alt *a = base->head; a && i < k; a = a->next, i++)
        mpz_init_set(s[i], a->nitems);
}

void rxe_policy_nitems(mpz_t out, struct rxe *base, int lo, int hi,
                       const int *floors, int k)
{
    mpz_set_ui(out, 0);
    if (hi < lo || lo < 0 || k <= 0) return;

    mpz_t *s = NEW(k, mpz_t);
    branch_sizes(base, s, k);

    // dp[j] = number of length-j strings drawn from the classes folded in so
    // far, each meeting its floor. Folding in class t of size s_t and floor f_t:
    //     dp'[j] = sum_{n=f_t..j} C(j,n) * s_t^n * dp[j-n]
    // -- n positions of class t chosen among the j (C(j,n)), each holding one of
    // s_t chars (s_t^n), over the dp[j-n] ways to fill the rest with the earlier
    // classes. After all k classes, dp[L] is the count at length L; the answer
    // is the sum over lo..hi. C(j,n) and s_t^n are advanced incrementally as n
    // rises, so each is one multiply/divide rather than a fresh computation.
    mpz_t *dp  = NEW(hi + 1, mpz_t);
    mpz_t *ndp = NEW(hi + 1, mpz_t);
    for (int j = 0; j <= hi; j++) { mpz_init(dp[j]); mpz_init(ndp[j]); }
    mpz_set_ui(dp[0], 1);

    mpz_t term, sp, binom;
    mpz_init(term); mpz_init(sp); mpz_init(binom);
    for (int t = 0; t < k; t++) {
        int ft = floors[t] < 0 ? 0 : floors[t];
        for (int j = 0; j <= hi; j++) {
            mpz_set_ui(ndp[j], 0);
            if (ft > j) continue;
            mpz_bin_uiui(binom, (unsigned long)j, (unsigned long)ft);  // C(j,ft)
            mpz_pow_ui(sp, s[t], (unsigned long)ft);                   // s_t^ft
            for (int n = ft; n <= j; n++) {
                mpz_mul(term, binom, sp);
                mpz_mul(term, term, dp[j - n]);
                mpz_add(ndp[j], ndp[j], term);
                if (n < j) {
                    mpz_mul_ui(binom, binom, (unsigned long)(j - n));   // C(j,n+1)
                    mpz_divexact_ui(binom, binom, (unsigned long)(n + 1));
                    mpz_mul(sp, sp, s[t]);                              // s_t^{n+1}
                }
            }
        }
        mpz_t *swap = dp; dp = ndp; ndp = swap;
    }
    for (int L = lo; L <= hi; L++) mpz_add(out, out, dp[L]);

    mpz_clear(term); mpz_clear(sp); mpz_clear(binom);
    for (int j = 0; j <= hi; j++) { mpz_clear(dp[j]); mpz_clear(ndp[j]); }
    rxe_mem_free(dp); rxe_mem_free(ndp);
    for (int i = 0; i < k; i++) mpz_clear(s[i]);
    rxe_mem_free(s);
}

void rxe_policy_make(struct rxe_node *node, int lo, int hi,
                     const int *floors, int k, int soaker)
{
    node->is_policy     = 1;
    node->rep_min       = lo;          // the length range lives in the repeat fields
    node->rep_max       = hi;
    node->rep_count     = 0;
    node->rep_digit     = NULL;
    node->rep_len       = NULL;
    node->rep_alloc     = 0;
    node->is_inf        = 0;           // a policy over finite classes is finite
    node->policy_nfloor = k;
    node->policy_soaker = soaker;
    node->policy_floor  = NEW(k, int);
    for (int i = 0; i < k; i++) node->policy_floor[i] = floors[i];
    mpz_set_ui(node->comb_index, 0);
    rxe_policy_nitems(node->nitems, node->rxe, lo, hi, floors, k);
}

// Slice 1: the count is validated, but the members are not yet walkable --
// report past-end so a '-e' over a policy pattern emits nothing rather than
// enumerating the wrong set. Slice 2 replaces both with the real unrank.
int rxe_policy_seek(struct rxe_node *node, const mpz_t pos)
{
    (void)node; (void)pos;
    return 1;
}

int rxe_policy_iterate(struct rxe_node *node)
{
    (void)node;
    return 1;
}
