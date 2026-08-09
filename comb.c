/*
 * librxe - a library for enumerating sets described by regexes, version 1.0.0
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

// Combinations and permutations of a subexpression's members.
//
// A subexpression describes a finite set of n members that the library can
// already seek into by index. '(re){{x}}' is then every way of choosing x of
// those n members -- C(n,x) of them, unordered -- and '(re){{x!}}' every
// ordered choice, P(n,x). Ranges sum the sizes; '{{*}}' is the full
// permutation, n!.
//
// The point is that both have a closed-form bijection with the integers, so
// the library's contract -- an index maps to an exact member and back, without
// enumerating the ones before it -- holds unchanged. A combination at index j
// is decoded through the combinatorial number system (combinadics); a
// permutation through the factorial number system. Neither walks the set.
//
// A choice is rendered exactly as a repetition is: the base subexpression is
// held once in node->rxe and seeked to each chosen index in turn, its indices
// living in the same rep_digit[] a repetition uses. Only the counting and the
// index decoding differ, which is all that is here.

#include "rxe.h"
#include "comb.h"
#include "repeat.h"

/* --------------------------- Counting ----------------------------------- */

// C(n,k) with n an arbitrary integer and k a small non-negative one. GMP gives
// zero when k exceeds n, which is exactly the answer we want.
static void bin(mpz_t out, const mpz_t n, int k)
{
    if (k < 0) { mpz_set_ui(out,0); return; }
    mpz_bin_ui(out,n,(unsigned long)k);
}

// The members of one size: P(n,k) = C(n,k)*k! ordered, or C(n,k) unordered.
static void size_count(mpz_t out, const mpz_t n, int size, int perm)
{
    bin(out,n,size);
    if (perm && size > 1) {
        mpz_t f;
        mpz_init(f);
        mpz_fac_ui(f,(unsigned long)size);
        mpz_mul(out,out,f);
        mpz_clear(f);
    }
}

void rxe_comb_nitems(mpz_t out, const mpz_t n, int lo, int hi, int perm)
{
    mpz_set_ui(out,0);
    if (hi < lo || lo < 0) return;
    mpz_t c;
    mpz_init(c);
    for (int s = lo; s <= hi; s++) {
        size_count(c,n,s,perm);
        mpz_add(out,out,c);
    }
    mpz_clear(c);
}

/* --------------------------- Decoding ----------------------------------- */

// Decode index j into an unordered choice of 'size' members, ascending, using
// the combinatorial number system: j = sum C(c_k, k), the c_k strictly
// decreasing, and the chosen indices are the c_k. Each c_k is the largest
// index whose binomial still fits, found by binary search so the base's
// cardinality is never enumerated.
static void decode_comb(mpz_t *digit, const mpz_t n, int size, mpz_t j)
{
    mpz_t upper,lo,hi,mid,cc;
    mpz_init_set(upper,n);         // the next index must be below this
    mpz_init(lo); mpz_init(hi); mpz_init(mid); mpz_init(cc);
    for (int k = size; k >= 1; k--) {
        mpz_set_ui(lo,k-1);        // C(k-1,k) is 0, always a valid floor
        mpz_sub_ui(hi,upper,1);
        while (mpz_cmp(lo,hi) < 0) {
            mpz_add(mid,lo,hi);
            mpz_add_ui(mid,mid,1);
            mpz_fdiv_q_2exp(mid,mid,1);       // ceil((lo+hi)/2)
            bin(cc,mid,k);
            if (mpz_cmp(cc,j) <= 0) mpz_set(lo,mid);
            else                    { mpz_sub_ui(hi,mid,1); }
        }
        bin(cc,lo,k);
        mpz_sub(j,j,cc);
        mpz_set(digit[k-1],lo);    // ascending: smallest ends up at digit[0]
        mpz_set(upper,lo);
    }
    mpz_clear(upper); mpz_clear(lo); mpz_clear(hi); mpz_clear(mid); mpz_clear(cc);
}

// Decode index j into an ordered choice of 'size' members, in lexicographic
// order of the sequences, using the factorial number system. At each position
// the rank among the still-unused indices is j divided by the number of ways
// to fill the rest; the rank is then turned into an actual index by stepping
// past the ones already used. Only 'size' indices are tracked, never n.
static void decode_perm(mpz_t *digit, const mpz_t n, int size, mpz_t j)
{
    mpz_t *used = NEW(size,mpz_t);
    for (int i = 0; i < size; i++) mpz_init(used[i]);
    int nused = 0;
    mpz_t block,rank,actual,rest,term;
    mpz_init(block); mpz_init(rank); mpz_init(actual);
    mpz_init(rest); mpz_init(term);
    for (int p = 0; p < size; p++) {
        // block = P(n-1-p, size-1-p): the falling factorial of the indices
        // still to place after this one is chosen.
        mpz_sub_ui(rest,n,(unsigned long)(p+1));      // n-1-p
        mpz_set_ui(block,1);
        for (int t = 0; t < size-1-p; t++) {
            mpz_sub_ui(term,rest,(unsigned long)t);
            mpz_mul(block,block,term);
        }
        mpz_tdiv_qr(rank,j,j,block);                  // rank in [0, n-p)
        // Turn the rank among the unused into an actual index. Walking the
        // used indices in ascending order, each one at or below the running
        // value shifts it up by one.
        mpz_set(actual,rank);
        for (int u = 0; u < nused; u++)
            if (mpz_cmp(used[u],actual) <= 0) mpz_add_ui(actual,actual,1);
        mpz_set(digit[p],actual);
        int ins = nused;
        while (ins > 0 && mpz_cmp(used[ins-1],actual) > 0) {
            mpz_set(used[ins],used[ins-1]);
            ins--;
        }
        mpz_set(used[ins],actual);
        nused++;
    }
    for (int i = 0; i < size; i++) mpz_clear(used[i]);
    rxe_mem_free(used);
    mpz_clear(block); mpz_clear(rank); mpz_clear(actual);
    mpz_clear(rest); mpz_clear(term);
}

// Place the choice at linear index 'pos' into the node's rep_digit/rep_count.
// The sizes lo..hi partition the index range into consecutive blocks in
// ascending order of size; find the block, then decode within it. Returns 1
// when pos is past the end.
static int comb_decode(struct rxe_node *node, const mpz_t pos)
{
    if (mpz_sgn(pos) < 0 || mpz_cmp(pos,node->nitems) >= 0) return 1;
    const mpz_t *n = (const mpz_t *)&node->rxe->nitems;
    mpz_t j,c;
    mpz_init_set(j,pos);
    mpz_init(c);
    int size = node->rep_min;
    for ( ; size <= node->rep_max; size++) {
        size_count(c,*n,size,node->comb_perm);
        if (mpz_cmp(j,c) < 0) break;
        mpz_sub(j,j,c);
    }
    node->rep_count = size;
    if (size > 0) {
        rxe_repeat_reserve(node,size);
        if (node->comb_perm) decode_perm(node->rep_digit,*n,size,j);
        else                 decode_comb(node->rep_digit,*n,size,j);
    }
    mpz_clear(j);
    mpz_clear(c);
    return 0;
}

/* --------------------------- Public API --------------------------------- */

void rxe_comb_make(struct rxe_node *node, int lo, int hi, int perm)
{
    node->is_comb   = 1;
    node->comb_perm = perm;
    node->rep_min   = lo;          // the size range lives in the repeat fields
    node->rep_max   = hi;
    node->rep_count = 0;
    node->rep_digit = NULL;
    node->rep_len   = NULL;
    node->rep_alloc = 0;
    node->is_inf    = 0;           // a choice over a finite set is finite
    mpz_set_ui(node->comb_index,0);
    rxe_comb_nitems(node->nitems,node->rxe->nitems,lo,hi,perm);
    if (mpz_sgn(node->nitems) > 0) {
        mpz_t z;
        mpz_init_set_ui(z,0);
        comb_decode(node,z);
        mpz_clear(z);
    }
}

int rxe_comb_seek(struct rxe_node *node, const mpz_t pos)
{
    if (comb_decode(node,pos)) return 1;
    mpz_set(node->comb_index,pos);
    return 0;
}

int rxe_comb_iterate(struct rxe_node *node)
{
    mpz_t next;
    int carry = 0;
    mpz_init(next);
    mpz_add_ui(next,node->comb_index,1);
    if (mpz_cmp(next,node->nitems) >= 0) { mpz_set_ui(next,0); carry = 1; }
    comb_decode(node,next);
    mpz_set(node->comb_index,next);
    mpz_clear(next);
    return carry;
}
