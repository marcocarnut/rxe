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

// Counted repetition.
//
// "x{r0,r1}" used to be built by writing the repetitions out: one alternation
// per repeat count, holding that many clones of the repeated subexpression.
// The set that describes is right, but the representation of it costs
// O(r1^2) copies -- a{1,2000} took 316MB, and a{1,20000} would have wanted
// about 30GB -- which put a ceiling on r1 that has nothing to do with the
// size of the set being described.
//
// A repetition is a numeral instead. If the repeated subexpression has b
// members then a run of exactly n of them has b^n, so the whole repetition
// has sum(b^j, j=r0..r1) members, and the repeat counts partition the index
// range into consecutive blocks in ascending order of n -- which is the order
// the written-out alternations produced, so the mapping is unchanged. Within
// a block the index is an n-digit numeral in base b, one digit per position.
//
// The state is therefore the repeat count and its digits: O(n) integers,
// where n is the length of the string being generated anyway. The
// subexpression is held once and seeked to digit i when position i is
// rendered, which is what lets a single copy stand in for all of them.

#include "rxe.h"
#include "repeat.h"

/* ------------------------------------------------------------------------ */

// The cardinality of the repetition, sum(base^j) for j from r0 to r1.
//
// The geometric closed form (b^(r1+1) - b^r0)/(b-1) is only valid for b >= 2:
// it divides by zero at b == 1 and reads 0^0 at b == 0. Those two are the
// degenerate cases where the sum is trivial anyway, so they are taken first
// and the closed form only ever sees the case it is good for.

void rxe_repeat_nitems(mpz_t out, const mpz_t base, int r0, int r1)
{
    // An unbounded repetition has no cardinality to report unless the thing
    // it repeats matches nothing, in which case only the empty run exists and
    // the answer is finite after all. Callers test rxe_repeat_is_infinite
    // first; this returns the finite answer for the one case there is.
    if (r1 == RXE_REP_UNBOUNDED) {
        mpz_set_ui(out, mpz_sgn(base) ? 0 : (r0 == 0 ? 1 : 0));
        return;
    }
    if (r1 < r0) { mpz_set_ui(out,0); return; }
    // A subexpression that matches nothing can still be repeated zero times,
    // which matches the empty string. Any other count is impossible.
    if (!mpz_sgn(base))          { mpz_set_ui(out, r0 == 0 ? 1 : 0); return; }
    // One member, so exactly one string per repeat count.
    if (!mpz_cmp_ui(base,1))     { mpz_set_ui(out, r1 - r0 + 1); return; }
    mpz_t hi,lo;
    mpz_init(hi);
    mpz_init(lo);
    mpz_pow_ui(hi,base,r1+1);
    mpz_pow_ui(lo,base,r0);
    mpz_sub(out,hi,lo);
    mpz_sub_ui(hi,base,1);
    mpz_tdiv_q(out,out,hi);
    mpz_clear(hi);
    mpz_clear(lo);
}

// Repeating something with no largest member gives a set with no largest
// member, unless there is nothing to repeat at all.

int rxe_repeat_is_infinite(struct rxe_node *node)
{
    // An endless body has no cardinality, so nitems is zero for it and cannot
    // stand in for "has any members at all".
    int body_endless = rxe_is_infinite(node->rxe);
    if (!body_endless && !mpz_sgn(node->rxe->nitems)) return 0;
    // No upper bound, and something to repeat: endless.
    if (node->rep_max == RXE_REP_UNBOUNDED) return 1;
    // Bounded, but each repetition draws from an endless body, so the whole
    // is endless too unless there are no repetitions at all.
    return body_endless && node->rep_max >= 1;
}

// Make room for at least 'want' position indices. An unbounded repetition
// cannot size this at parse time, and even a bounded one is better off not
// doing so: 'a{1,1000000}' would otherwise reserve a million integers to
// enumerate a set whose first element is one character long.

void rxe_repeat_reserve(struct rxe_node *node, int want)
{
    if (want <= node->rep_alloc) return;
    int i, n = node->rep_alloc ? node->rep_alloc : 8;
    while (n < want) n *= 2;
    mpz_t *fresh = NEW(n,mpz_t);
    for (i=0;i<node->rep_alloc;i++) {
        // mpz_t is an array type, so this hands the limbs over rather than
        // copying them; the old entries must not be cleared afterwards.
        fresh[i][0] = node->rep_digit[i][0];
    }
    for (i=node->rep_alloc;i<n;i++) mpz_init(fresh[i]);
    if (node->rep_digit) rxe_mem_free(node->rep_digit);
    node->rep_digit = fresh;
    // The parallel array of lengths, used only when the expression is
    // enumerated shortest first: there a position is addressed by the length
    // it takes and its index among the members of that length, rather than by
    // one index into the body's whole ordering.
    int *lens = NEW(n,int);
    for (i=0;i<node->rep_alloc;i++) lens[i] = node->rep_len[i];
    for (i=node->rep_alloc;i<n;i++) lens[i] = 0;
    if (node->rep_len) rxe_mem_free(node->rep_len);
    node->rep_len = lens;
    node->rep_alloc = n;
}

// Turn an ordinary subexpression node into a repetition of it. The caller has
// already moved the repeated thing into node->rxe and set node->nitems to its
// cardinality; on return node->nitems is the cardinality of the repetition,
// or zero if there is no such number because the repetition is unbounded.

void rxe_repeat_make(struct rxe_node *node, int r0, int r1)
{
    node->is_repeat = 1;
    node->rep_min   = r0;
    node->rep_max   = r1;
    node->rep_count = r0;
    node->rep_digit = NULL;
    node->rep_len   = NULL;
    node->rep_alloc = 0;
    node->is_inf    = rxe_repeat_is_infinite(node);
    if (r0 > 0) rxe_repeat_reserve(node,r0);
    rxe_repeat_nitems(node->nitems,node->rxe->nitems,r0,r1);
}

void rxe_repeat_free(struct rxe_node *node)
{
    if (!node->rep_digit) return;
    int i;
    for (i=0;i<node->rep_alloc;i++) mpz_clear(node->rep_digit[i]);
    rxe_mem_free(node->rep_digit);
    node->rep_digit = NULL;
    if (node->rep_len) rxe_mem_free(node->rep_len);
    node->rep_len = NULL;
    node->rep_alloc = 0;
}

// Position i of a run of n counts from the right by default, so that the last
// repetition is the least significant digit, exactly as the last node of an
// alternation is. Under (?L) it counts from the left instead.

static int digit_at(int n, int significance, int l2r)
{
    return l2r ? significance : n-1-significance;
}

// Select the item at 'pos' within this repetition. Returns 1 if pos is past
// the end, in which case the node's state is left alone.

int rxe_repeat_seek(struct rxe_node *node, const mpz_t pos, int l2r)
{
    struct rxe *sub = node->rxe;
    int unbounded = node->rep_max == RXE_REP_UNBOUNDED;
    int n = node->rep_min, i, rc = 1;
    mpz_t p,block,r;
    mpz_init_set(p,pos);
    mpz_init(block);
    mpz_init(r);
    if (mpz_sgn(p) < 0) goto done;
    if (!mpz_sgn(sub->nitems)) {
        // Nothing to repeat: only a run of length zero exists, and only if it
        // is allowed. This is the one way an unbounded repetition can turn
        // out to be finite.
        if (node->rep_min != 0 || mpz_sgn(p)) goto done;
        node->rep_count = 0;
        rc = 0;
        goto done;
    }
    if (!mpz_cmp_ui(sub->nitems,1)) {
        // One string per count, so pos selects the count directly. Unbounded,
        // that is every count there is, and the mapping is the identity.
        if (!unbounded && mpz_cmp_ui(p,node->rep_max-node->rep_min+1) >= 0)
            goto done;
        // A run this long has to be renderable before it can be selected, and
        // an index that does not fit in a machine word never will be.
        if (!mpz_fits_slong_p(p)) goto done;
        node->rep_count = node->rep_min + (int)mpz_get_ui(p);
        rxe_repeat_reserve(node,node->rep_count);
        for (i=0;i<node->rep_count;i++) mpz_set_ui(node->rep_digit[i],0);
        rc = 0;
        goto done;
    }
    // Walk the repeat counts in ascending order, subtracting each block as it
    // is passed. The base is two or more here, so the blocks grow
    // geometrically and this ends after about log_base(pos) steps -- which is
    // what lets an unbounded repetition be walked at all, the loop finding its
    // own end rather than running out of counts.
    mpz_pow_ui(block,sub->nitems,node->rep_min);
    for (n=node->rep_min;unbounded || n<=node->rep_max;n++) {
        if (mpz_cmp(p,block) < 0) break;
        mpz_sub(p,p,block);
        mpz_mul(block,block,sub->nitems);
    }
    if (!unbounded && n > node->rep_max) goto done;
    node->rep_count = n;
    rxe_repeat_reserve(node,n);
    // p is now an n-digit numeral in base sub->nitems. Peel the digits off
    // least significant first and store each at the position it drives.
    for (i=0;i<n;i++) {
        mpz_tdiv_qr(p,r,p,sub->nitems);
        mpz_set(node->rep_digit[digit_at(n,i,l2r)],r);
    }
    rc = 0;
done:
    mpz_clear(p);
    mpz_clear(block);
    mpz_clear(r);
    return rc;
}

// Step to the next item. Returns 1 on carry out, having wrapped back to the
// first, exactly as rxe_iterate does.

int rxe_repeat_iterate(struct rxe_node *node, int l2r)
{
    struct rxe *sub = node->rxe;
    int i, n = node->rep_count;
    // Nothing to repeat: the empty run is the only item there is, so every
    // step carries. Without this the count would walk up into repeat counts
    // whose blocks hold no strings at all.
    if (!mpz_sgn(sub->nitems)) return 1;
    // Ripple through the digits, least significant first.
    for (i=0;i<n;i++) {
        mpz_t *d = &node->rep_digit[digit_at(n,i,l2r)];
        mpz_add_ui(*d,*d,1);
        if (mpz_cmp(*d,sub->nitems) < 0) return 0;
        mpz_set_ui(*d,0);
    }
    // Every digit wrapped, so the run of this length is exhausted; the next
    // block is the next repeat count up. There is always one when the
    // repetition is unbounded, which is why it never carries out.
    int carry = 0;
    node->rep_count++;
    // Unbounded, there is always a next count, so it never carries out.
    if (node->rep_max != RXE_REP_UNBOUNDED &&
        node->rep_count > node->rep_max) {
        node->rep_count = node->rep_min;
        carry = 1;
    }
    // The indices are allocated on demand, so a longer run than any reached
    // so far has to make room for itself before it can be cleared.
    rxe_repeat_reserve(node,node->rep_count);
    for (i=0;i<node->rep_count;i++) mpz_set_ui(node->rep_digit[i],0);
    return carry;
}
