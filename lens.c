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

// Counting an expression's members by length, and addressing them that way.
//
// A finite expression is a numeral and place value orders it. That does not
// carry over to an infinite one: an unbounded quantifier is a place with no
// largest digit, so anything to the left of it is never reached. The first
// answer to that was a pairing function, which spreads one index across
// several endless dimensions by walking diagonals. It is a bijection and it
// reaches everything, but the order it produces is only shortest-first when
// each dimension's index happens to be the length it contributes. Worse, the
// pairings nest, and each level squares the index: in '(\d+,)*' a list of
// five one-digit numbers sits at index 5.8e18, where counting by length puts
// it below 2.1e9. The set is enumerable but not walkable.
//
// Counting by length fixes both. Ask instead how many members an expression
// has of each length; then walking L upwards and enumerating the members of
// each length in turn visits the whole set shortest first, and the index of
// anything short is small. The four constructions are what you would expect:
//
//   a character class     one length, count[1] = how many characters
//   concatenation         convolution of the positions' counts
//   alternation           sum of the branches' counts
//   repetition x{r0,r1}   sum over n of the n-fold convolution of x
//
// Nothing is computed until it is asked for, and then only as far as asked.
// That is what makes it affordable: the counts of '[a-z]{1,20000}' are 26^L,
// and enumerating the first few thousand members asks about L up to a dozen,
// never about the twenty thousand. It is also why this does not replace the
// cardinality for finite expressions, where it would be strictly worse: one
// number of 28,300 digits, against twenty thousand of them.
//
// One shape cannot be counted this way and is refused in the parser: an
// unbounded repetition whose body can match nothing at all. '(a*)*' derives
// the empty string infinitely many ways, so count[0] does not converge. That
// is the same restriction Perl's matcher imposes on an empty loop body, and
// it is narrow: '(\d+,)*' has a body of at least two characters and is fine.
//
// A second shape can be counted but not by this scheme: a backreference ties
// its length to the group it names, so the positions of a concatenation stop
// being independent and the convolution above is wrong. Rather than refuse
// those, an expression holding one keeps the pairing order -- still a
// bijection onto the whole set, just not shortest first. See
// rxe_is_shortlex().

#include <string.h>
#include "rxe.h"
#include "rxe_alt.h"
#include "lens.h"
#include "repeat.h"

/* ------------------------ Macro-Defined Constants ----------------------- */

// Refuse to grow a length table past this. Nothing legitimate approaches it:
// a member this long cannot be printed and the count of them is astronomical.
// It exists so that a pathological expression fails rather than allocates
// until it is killed.

#define LENS_MAX_LENGTH          100000

/* ------------------------------------------------------------------------ */

void rxe_lens_init(struct rxe_lens *lens)
{
    lens->max   = -1;
    lens->alloc = 0;
    lens->count = NULL;
}

void rxe_lens_free(struct rxe_lens *lens)
{
    int i;
    for (i=0;i<lens->alloc;i++) mpz_clear(lens->count[i]);
    if (lens->count) rxe_mem_free(lens->count);
    rxe_lens_init(lens);
}

// Make room for lengths 0..want, keeping whatever is already known.

static void lens_reserve(struct rxe_lens *lens, int want)
{
    if (want < lens->alloc) return;
    int i, n = lens->alloc ? lens->alloc : 8;
    while (n <= want) n *= 2;
    mpz_t *fresh = NEW(n,mpz_t);
    // mpz_t is an array type, so this hands the limbs over rather than
    // copying them; the old entries must not be cleared afterwards.
    for (i=0;i<lens->alloc;i++) fresh[i][0] = lens->count[i][0];
    for (i=lens->alloc;i<n;i++) mpz_init(fresh[i]);
    if (lens->count) rxe_mem_free(lens->count);
    lens->count = fresh;
    lens->alloc = n;
}

// The count at one length, zero for anything not computed or out of range.

static void lens_at(mpz_t out, struct rxe_lens *lens, int L)
{
    if (L < 0 || L > lens->max) mpz_set_ui(out,0);
    else mpz_set(out,lens->count[L]);
}

/* ---------------------------- Counting ---------------------------------- */

static void lens_node(struct rxe_node *node, int L);
static void lens_rest(struct rxe_node *node, int L);

// An alternation's members by length: the convolution of its positions,
// which is exactly the 'rest' table of the most significant one.

void rxe_lens_alt(struct rxe_alt *alt, int L)
{
    if (L <= alt->lens.max) return;
    int i, from = alt->lens.max+1;
    int l2r = alt->owner && (alt->owner->flags & RXE_FLAG_LEFT_TO_RIGHT);
    struct rxe_node *top = l2r ? alt->tail : alt->head;
    lens_reserve(&alt->lens,L);
    for (i=from;i<=L;i++) mpz_set_ui(alt->lens.count[i],0);
    if (!top) {
        // No positions at all, so it matches the empty string and nothing
        // else. Not the same as matching nothing, which is count[0] == 0.
        if (from == 0) mpz_set_ui(alt->lens.count[0],1);
        alt->lens.max = L;
        return;
    }
    lens_node(top,L);
    lens_rest(top,L);
    mpz_t sum,a,b;
    mpz_init(sum);
    mpz_init(a);
    mpz_init(b);
    for ( i = from ; i <= L ; i++ ) {
        int l;
        mpz_set_ui(sum,0);
        for (l=0;l<=i;l++) {
            lens_at(a,&top->lens,l);
            if (!mpz_sgn(a)) continue;
            lens_at(b,&top->rest,i-l);
            mpz_addmul(sum,a,b);
        }
        mpz_set(alt->lens.count[i],sum);
    }
    alt->lens.max = L;
    mpz_clear(sum);
    mpz_clear(a);
    mpz_clear(b);
}

// Everything strictly less significant than this position, convolved. Under
// the default direction that is the positions after it; under (?L) it is the
// ones before. Either way it is what the split search divides by.

static void lens_rest(struct rxe_node *node, int L)
{
    if (L <= node->rest.max) return;
    int l2r = node->owner && node->owner->owner &&
              (node->owner->owner->flags & RXE_FLAG_LEFT_TO_RIGHT);
    struct rxe_node *next = l2r ? node->prev : node->next;
    int i, from = node->rest.max+1;
    lens_reserve(&node->rest,L);
    for (i=from;i<=L;i++) mpz_set_ui(node->rest.count[i],0);
    if (!next) {
        // Nothing below it, so the only way to spend no more length is to
        // spend none: the multiplicative identity.
        if (from == 0) mpz_set_ui(node->rest.count[0],1);
        node->rest.max = L;
        return;
    }
    lens_node(next,L);
    lens_rest(next,L);
    mpz_t sum,a,b;
    mpz_init(sum);
    mpz_init(a);
    mpz_init(b);
    for ( i = from ; i <= L ; i++ ) {
        int l;
        mpz_set_ui(sum,0);
        for (l=0;l<=i;l++) {
            lens_at(a,&next->lens,l);
            if (!mpz_sgn(a)) continue;
            lens_at(b,&next->rest,i-l);
            mpz_addmul(sum,a,b);
        }
        mpz_set(node->rest.count[i],sum);
    }
    node->rest.max = L;
    mpz_clear(sum);
    mpz_clear(a);
    mpz_clear(b);
}

// The n-fold convolution of the repeated body, W(n,L), written into 'row'
// from the previous row. Used both to count a repetition and to pick which
// repeat count an index falls in.

static void rep_step(mpz_t *row, mpz_t *prev, struct rxe_lens *body, int L)
{
    int i,l;
    mpz_t a,b;
    mpz_init(a);
    mpz_init(b);
    for (i=0;i<=L;i++) {
        mpz_set_ui(row[i],0);
        for (l=0;l<=i;l++) {
            lens_at(a,body,l);
            if (!mpz_sgn(a)) continue;
            mpz_addmul(row[i],a,prev[i-l]);
        }
    }
    mpz_clear(a);
    mpz_clear(b);
}

// How many repeat counts can contribute at length L. A body that cannot match
// the empty string spends at least one character per repetition, so no more
// than L of them fit however high the bound goes -- which is what lets an
// unbounded repetition be counted at all. A body that can match empty is only
// bounded by rep_max, and the parser refuses the case where there is none.

static int rep_top(struct rxe_node *node, int L)
{
    mpz_t z;
    int can_be_empty;
    mpz_init(z);
    lens_at(z,&node->rxe->lens,0);
    can_be_empty = mpz_sgn(z) != 0;
    mpz_clear(z);
    // Unbounded, the body must cost at least one character -- the parser
    // refuses it otherwise -- so no more than L repetitions can fit.
    if (node->rep_max == RXE_REP_UNBOUNDED) return L;
    if (!can_be_empty && node->rep_max > L) return L;
    return node->rep_max;
}

// Walk the repeat counts, handing each row of W to 'visit' until it says
// stop. Shared by counting (which adds them all up) and seeking (which stops
// at the one holding the index).

static void rep_walk(struct rxe_node *node, int L, void *ctx,
                     int (*visit)(void *ctx, int n, mpz_t *row))
{
    int n, hi = rep_top(node,L);
    int i;
    mpz_t *cur = NEW(L+1,mpz_t);
    mpz_t *prev = NEW(L+1,mpz_t);
    for (i=0;i<=L;i++) { mpz_init(cur[i]); mpz_init_set_ui(prev[i],0); }
    mpz_set_ui(prev[0],1);                       // W(0,L) is 1 at L == 0
    for (n=0;n<=hi;n++) {
        if (n) rep_step(cur,prev,&node->rxe->lens,L);
        else   for (i=0;i<=L;i++) mpz_set(cur[i],prev[i]);
        if (n >= node->rep_min && visit(ctx,n,cur)) break;
        for (i=0;i<=L;i++) mpz_set(prev[i],cur[i]);
    }
    for (i=0;i<=L;i++) { mpz_clear(cur[i]); mpz_clear(prev[i]); }
    rxe_mem_free(cur);
    rxe_mem_free(prev);
}

// True when every member of the repeated body is the same length, which is
// the case that matters for cost: 'a*' at index n needs length n, so the
// general sweep below would be quadratic in the index. A finite body whose
// count at one length accounts for its whole cardinality has no members of
// any other length.

static int body_fixed_length(struct rxe_node *node, int L, int *m)
{
    struct rxe *body = node->rxe;
    int i, hi = L < body->lens.max ? L : body->lens.max;
    if (rxe_is_infinite(body)) return 0;
    for (i=1;i<=hi;i++) {
        if (!mpz_sgn(body->lens.count[i])) continue;
        // The shortest non-empty length. If it already accounts for the whole
        // cardinality there are no members of any other length -- including
        // the empty string, which would otherwise be counted at zero.
        if (mpz_cmp(body->lens.count[i],body->nitems)) return 0;
        *m = i;
        return 1;
    }
    return 0;
}

// One position's members by length.

static void lens_node(struct rxe_node *node, int L)
{
    if (L <= node->lens.max) return;
    lens_reserve(&node->lens,L);
    int i;
    for ( i = node->lens.max+1 ; i <= L ; i++ )
        mpz_set_ui(node->lens.count[i],0);
    int from = node->lens.max+1;
    node->lens.max = L;
    if (node->is_repeat) {
        int m;
        rxe_lens_rxe(node->rxe,L);
        if (body_fixed_length(node,L,&m)) {
            // n repetitions cost exactly n*m, so a length picks the count and
            // the number of members is a plain power.
            mpz_t b;
            mpz_init(b);
            lens_at(b,&node->rxe->lens,m);
            for (i=from;i<=L;i++) {
                int n = i/m;
                if (i % m || n < node->rep_min) continue;
                if (node->rep_max != RXE_REP_UNBOUNDED && n > node->rep_max)
                    continue;
                mpz_pow_ui(node->lens.count[i],b,n);
            }
            mpz_clear(b);
        } else {
            // Accumulate the n-fold convolutions over every length at once.
            // Doing it per length would repeat this whole sweep for each.
            int n, hi = rep_top(node,L);
            mpz_t *w = NEW(L+1,mpz_t), *t = NEW(L+1,mpz_t);
            for (i=0;i<=L;i++) { mpz_init(w[i]); mpz_init(t[i]); }
            mpz_set_ui(w[0],1);
            for (n=0;n<=hi;n++) {
                if (n) {
                    mpz_t *swap;
                    rep_step(t,w,&node->rxe->lens,L);
                    swap = w; w = t; t = swap;
                }
                if (n < node->rep_min) continue;
                for (i=from;i<=L;i++)
                    mpz_add(node->lens.count[i],node->lens.count[i],w[i]);
            }
            for (i=0;i<=L;i++) { mpz_clear(w[i]); mpz_clear(t[i]); }
            rxe_mem_free(w);
            rxe_mem_free(t);
        }
    } else if (node->rxe) {
        // A backreference is handled by the caller falling back wholesale, so
        // reaching here means an ordinary subexpression.
        rxe_lens_rxe(node->rxe,L);
        for (i=from;i<=L;i++) lens_at(node->lens.count[i],&node->rxe->lens,i);
    } else if (node->is_dict) {
        // Each word contributes one member at its own length. A word is
        // counted in the one call whose [from,L] range first covers its
        // length, so a single pass over the words is correct.
        int k;
        for (k=0;k<node->nwords;k++) {
            int wl = (int)strlen(node->words[k]);
            if (wl >= from && wl <= L)
                mpz_add_ui(node->lens.count[wl],node->lens.count[wl],1);
        }
    } else if (node->len) {
        // A character class is one character long, whatever it holds.
        if (from <= 1 && L >= 1) mpz_set_ui(node->lens.count[1],node->len);
    } else {
        // Nothing to contribute: matches the empty string only.
        if (from == 0) mpz_set_ui(node->lens.count[0],1);
    }
}

// An expression's members by length: the sum over its alternations.

void rxe_lens_rxe(struct rxe *rxe, int L)
{
    if (L <= rxe->lens.max) return;
    if (L > LENS_MAX_LENGTH) return;
    // Grow in doublings. rxe_seek_shortlex walks the lengths upward one at a
    // time, and a repetition's counts are built by a sweep over every length
    // at once rather than incrementally, so answering each request exactly
    // would rebuild that sweep once per length and turn a quadratic job cubic.
    if (L < 2*rxe->lens.max) L = 2*rxe->lens.max;
    if (L > LENS_MAX_LENGTH) L = LENS_MAX_LENGTH;
    lens_reserve(&rxe->lens,L);
    int i;
    for ( i = rxe->lens.max+1 ; i <= L ; i++ ) mpz_set_ui(rxe->lens.count[i],0);
    int from = rxe->lens.max+1;
    rxe->lens.max = L;
    struct rxe_alt *alt;
    for ( alt = rxe->head ; alt ; alt = alt->next ) {
        rxe_lens_alt(alt,L);
        for (i=from;i<=L;i++)
            mpz_add(rxe->lens.count[i],rxe->lens.count[i],alt->lens.count[i]);
    }
}

int rxe_matches_empty(struct rxe *rxe)
{
    mpz_t z;
    int rc;
    mpz_init(z);
    rxe_count_at_length(z,rxe,0);
    rc = mpz_sgn(z) != 0;
    mpz_clear(z);
    return rc;
}

void rxe_count_at_length(mpz_t out, struct rxe *rxe, int L)
{
    if (L < 0 || L > LENS_MAX_LENGTH) { mpz_set_ui(out,0); return; }
    rxe_lens_rxe(rxe,L);
    lens_at(out,&rxe->lens,L);
}

/* ----------------------------- Seeking ---------------------------------- */

static int seek_node(struct rxe_node *node, int L, const mpz_t idx);

// Pick the split of L between this position and everything below it, then the
// member within. Lengths are tried with the most significant position taking
// as much as it can first, so that 'a*b*' comes out aa, ab, bb within a
// length rather than the other way about.

static int seek_from(struct rxe_node *node, int L, const mpz_t idx)
{
    int rc = 1, l;
    mpz_t r,a,b,block,q;
    mpz_init_set(r,idx);
    mpz_init(a);
    mpz_init(b);
    mpz_init(block);
    mpz_init(q);
    if (!node) {
        // Nothing left to place, so the only valid call is for no length and
        // the first (and only) member.
        rc = (L == 0 && !mpz_sgn(r)) ? 0 : 1;
        goto done;
    }
    lens_node(node,L);
    lens_rest(node,L);
    for (l=L;l>=0;l--) {
        lens_at(a,&node->lens,l);
        if (!mpz_sgn(a)) continue;
        lens_at(b,&node->rest,L-l);
        if (!mpz_sgn(b)) continue;
        mpz_mul(block,a,b);
        if (mpz_cmp(r,block) >= 0) { mpz_sub(r,r,block); continue; }
        // Within the split, this position is the more significant digit.
        mpz_tdiv_qr(q,r,r,b);
        int l2r = node->owner && node->owner->owner &&
                  (node->owner->owner->flags & RXE_FLAG_LEFT_TO_RIGHT);
        if (seek_node(node,l,q)) goto done;
        rc = seek_from(l2r ? node->prev : node->next,L-l,r);
        goto done;
    }
done:
    mpz_clear(r);
    mpz_clear(a);
    mpz_clear(b);
    mpz_clear(block);
    mpz_clear(q);
    return rc;
}

struct rep_seek_ctx {
    int    L;
    mpz_t  r;
    int    n;
    int    found;
};

static int rep_seek_visit(void *v, int n, mpz_t *row)
{
    struct rep_seek_ctx *c = v;
    if (mpz_cmp(c->r,row[c->L]) < 0) { c->n = n; c->found = 1; return 1; }
    mpz_sub(c->r,c->r,row[c->L]);
    return 0;
}

// Spread L over the n positions of a repetition and record what each one
// takes. The positions are identical copies of the body, so the split search
// divides by W(remaining positions, remaining length) rather than by a 'rest'
// table.

static int seek_rep_positions(struct rxe_node *node, int n, int L, mpz_t r,
                              int l2r)
{
    int rc = 0, i, k;
    if (n <= 0) return (L == 0 && !mpz_sgn(r)) ? 0 : 1;
    // W(k,L) for k up to n, so that the search can divide by the tail.
    mpz_t **w = NEW(n+1,mpz_t *);
    for (k=0;k<=n;k++) {
        w[k] = NEW(L+1,mpz_t);
        for (i=0;i<=L;i++) mpz_init(w[k][i]);
    }
    mpz_set_ui(w[0][0],1);
    for (k=1;k<=n;k++) rep_step(w[k],w[k-1],&node->rxe->lens,L);
    int left = L;
    mpz_t a,b,block,q;
    mpz_init(a);
    mpz_init(b);
    mpz_init(block);
    mpz_init(q);
    for (i=0;i<n;i++) {
        // Positions are visited most significant first, and the most
        // significant takes as much of the length as it can. Under the
        // default direction that is the first of them, as it is for the
        // positions of an ordinary concatenation.
        int pos = l2r ? n-1-i : i;
        int l, taken = -1;
        for (l=left;l>=0;l--) {
            lens_at(a,&node->rxe->lens,l);
            if (!mpz_sgn(a)) continue;
            mpz_set(b,w[n-1-i][left-l]);
            if (!mpz_sgn(b)) continue;
            mpz_mul(block,a,b);
            if (mpz_cmp(r,block) >= 0) { mpz_sub(r,r,block); continue; }
            mpz_tdiv_qr(q,r,r,b);
            taken = l;
            break;
        }
        if (taken < 0) { rc = 1; break; }
        node->rep_len[pos] = taken;
        mpz_set(node->rep_digit[pos],q);
        left -= taken;
    }
    if (!rc && (left || mpz_sgn(r))) rc = 1;
    mpz_clear(a);
    mpz_clear(b);
    mpz_clear(block);
    mpz_clear(q);
    for (k=0;k<=n;k++) {
        for (i=0;i<=L;i++) mpz_clear(w[k][i]);
        rxe_mem_free(w[k]);
    }
    rxe_mem_free(w);
    return rc;
}

int rxe_repeat_seek_at_length(struct rxe_node *node, int L, const mpz_t idx,
                              int l2r)
{
    struct rep_seek_ctx c;
    int rc, fixed_m;
    rxe_lens_rxe(node->rxe,L);
    // Settle the repeat count before walking for it where arithmetic can give
    // it. This is the shape whose length grows with the index -- 'a*' at index
    // n is n characters long -- so a linear walk here would make the whole
    // enumeration quadratic in the number of elements asked for.
    if (body_fixed_length(node,L,&fixed_m)) {
        // The length names the count outright, and every position takes the
        // same share of it, so there is no split to search either: the index
        // is an ordinary numeral over the positions.
        int i;
        mpz_t b,q,r;
        int n = L/fixed_m;
        if (L % fixed_m || n < node->rep_min) return 1;
        if (node->rep_max != RXE_REP_UNBOUNDED && n > node->rep_max) return 1;
        if (rxe_repeat_reserve(node,n)) return 1;
        node->rep_count = n;
        mpz_init(b);
        mpz_init(q);
        mpz_init_set(r,idx);
        lens_at(b,&node->rxe->lens,fixed_m);
        rc = 0;
        // Peeled least significant digit first, so i counts significance and
        // the position it drives is the last one under the default direction.
        for (i=0;i<n;i++) {
            int pos = l2r ? i : n-1-i;
            if (!mpz_sgn(b)) { rc = 1; break; }
            mpz_tdiv_qr(q,r,r,b);
            node->rep_len[pos] = fixed_m;
            mpz_set(node->rep_digit[pos],r);
            mpz_set(r,q);
        }
        if (!rc && mpz_sgn(r)) rc = 1;
        mpz_clear(b);
        mpz_clear(q);
        mpz_clear(r);
        return rc;
    }
    c.L = L;
    c.n = 0;
    c.found = 0;
    mpz_init_set(c.r,idx);
    rep_walk(node,L,&c,rep_seek_visit);
    if (!c.found) { mpz_clear(c.r); return 1; }
    if (rxe_repeat_reserve(node,c.n)) { mpz_clear(c.r); return 1; }
    node->rep_count = c.n;
    rc = seek_rep_positions(node,c.n,L,c.r,l2r);
    mpz_clear(c.r);
    return rc;
}

static int seek_node(struct rxe_node *node, int L, const mpz_t idx)
{
    int l2r = node->owner && node->owner->owner &&
              (node->owner->owner->flags & RXE_FLAG_LEFT_TO_RIGHT);
    if (node->is_repeat)
        return rxe_repeat_seek_at_length(node,L,idx,l2r);
    if (node->rxe)
        return rxe_seek_at_length(node->rxe,L,idx);
    if (node->is_dict) {
        // The idx-th word of exactly length L, counted in the order the words
        // are stored -- the same order the finite path uses, so the two agree.
        unsigned long want = mpz_get_ui(idx);
        int k;
        if (!mpz_fits_ulong_p(idx)) return 1;
        for (k=0;k<node->nwords;k++) {
            if ((int)strlen(node->words[k]) != L) continue;
            if (want == 0) { node->iterator = k; return 0; }
            want--;
        }
        return 1;
    }
    if (node->len) {
        if (L != 1 || mpz_cmp_ui(idx,node->len) >= 0) return 1;
        node->iterator = (int)mpz_get_ui(idx);
        return 0;
    }
    return (L == 0 && !mpz_sgn(idx)) ? 0 : 1;
}

int rxe_seek_at_length(struct rxe *rxe, int L, const mpz_t idx)
{
    struct rxe_alt *alt;
    mpz_t r,c;
    int rc = 1;
    if (!rxe || L < 0 || mpz_sgn(idx) < 0) return 1;
    rxe_lens_rxe(rxe,L);
    mpz_init_set(r,idx);
    mpz_init(c);
    for ( alt = rxe->head ; alt ; alt = alt->next ) {
        rxe_lens_alt(alt,L);
        lens_at(c,&alt->lens,L);
        if (!mpz_sgn(c)) continue;
        if (mpz_cmp(r,c) >= 0) { mpz_sub(r,r,c); continue; }
        rxe->curr = alt;
        {
            int l2r = rxe->flags & RXE_FLAG_LEFT_TO_RIGHT;
            rc = seek_from(l2r ? alt->tail : alt->head,L,r);
        }
        break;
    }
    mpz_clear(r);
    mpz_clear(c);
    return rc;
}

// The whole point: walk the lengths in order, and within each one the members
// in order, so that the set comes out shortest first.

int rxe_seek_shortlex(struct rxe *rxe, const mpz_t pos)
{
    int L, rc;
    mpz_t r,c;
    if (!rxe || mpz_sgn(pos) < 0) return 1;
    mpz_init_set(r,pos);
    mpz_init(c);
    for (L=0;L<=LENS_MAX_LENGTH;L++) {
        rxe_count_at_length(c,rxe,L);
        if (mpz_cmp(r,c) < 0) {
            rc = rxe_seek_at_length(rxe,L,r);
            mpz_clear(r);
            mpz_clear(c);
            return rc;
        }
        mpz_sub(r,r,c);
    }
    mpz_clear(r);
    mpz_clear(c);
    return 1;
}

/* ----------------------------- Ranking ---------------------------------- */

// The inverse of the shortlex seek. Given a string, find the shortlex index it
// sits at, by the same length-split arithmetic run backwards: count and skip
// the members shorter than it, then within its own length undo the split of
// the length among the positions. Each function mirrors the seek of the same
// name. Only fixed-length repeat bodies and the default direction are handled;
// the rest is refused up front so nothing partial is ever visited.

static int rank_at_length(struct rxe *rxe, const char *s, int off, int L,
                          rxe_rank_visit visit, void *ctx);
static int rank_from(struct rxe_node *node, const char *s, int off, int L,
                     rxe_rank_visit visit, void *ctx);

// The body's single member length, if it has one, independent of any query
// length: probe the body's lengths until the shortest non-empty one turns up,
// then it is fixed iff that length holds the body's whole cardinality. Unlike
// body_fixed_length, which is told a length, this finds its own, so it answers
// even for the empty string, where the query length says nothing.
static int repeat_body_fixed(struct rxe_node *node, int *m)
{
    struct rxe *body = node->rxe;
    int L = 1;
    for (;;) {
        rxe_lens_rxe(body, L);
        int hi = L < body->lens.max ? L : body->lens.max;
        for (int i = 1; i <= hi; i++)
            if (mpz_sgn(body->lens.count[i])) {      // shortest non-empty length
                *m = i;
                return !mpz_cmp(body->lens.count[i], body->nitems);
            }
        if (!mpz_cmp(body->lens.count[0], body->nitems)) return 0;  // empty only
        if (L >= LENS_MAX_LENGTH) return 0;
        L *= 2;
    }
}

// Only fixed-length repeat bodies and the default direction are rankable so
// far. Checked over the whole tree before any index is built, so a set outside
// that is refused whole rather than answered in part.
static int shortlex_rankable(struct rxe *rxe, int len)
{
    if (rxe->flags & RXE_FLAG_LEFT_TO_RIGHT) return 0;
    for (struct rxe_alt *alt = rxe->head; alt; alt = alt->next)
        for (struct rxe_node *node = alt->head; node; node = node->next) {
            int m;
            if (node->is_repeat && !repeat_body_fixed(node, &m)) return 0;
            if (node->rxe && !node->is_backref
                    && !shortlex_rankable(node->rxe, len))
                return 0;
        }
    return 1;
}

// A repetition of a fixed-length body: the length names the count outright and
// every position takes the same share m, so the string splits into n chunks of
// m with no search, and the index is a numeral over the chunks' own
// within-length ranks -- the last chunk least significant, as the odometer runs.
struct rep_len_ctx {
    struct rxe *body;
    const char *s;
    int off, m, n;
    mpz_srcptr base;                       // members of the body at length m
    rxe_rank_visit visit;
    void *ctx;
};
static int rep_len_rec(struct rep_len_ctx *c, int p, mpz_srcptr value);

struct rep_len_chunk { struct rep_len_ctx *c; int p; mpz_srcptr value; };
static int rep_len_chunk_visit(void *v, const mpz_t qd)
{
    struct rep_len_chunk *k = v;
    mpz_t nv;
    mpz_init(nv);
    mpz_mul(nv, k->value, k->c->base);     // value = value*base + qd
    mpz_add(nv, nv, qd);
    int stop = rep_len_rec(k->c, k->p + 1, nv);
    mpz_clear(nv);
    return stop;
}
static int rep_len_rec(struct rep_len_ctx *c, int p, mpz_srcptr value)
{
    if (p == c->n) return c->visit(c->ctx, value);
    struct rep_len_chunk k = { c, p, value };
    return rank_at_length(c->body, c->s, c->off + p * c->m, c->m,
                          rep_len_chunk_visit, &k);
}
static int rank_repeat_len(struct rxe_node *node, const char *s, int off, int L,
                           rxe_rank_visit visit, void *ctx)
{
    struct rxe *body = node->rxe;
    int m;
    if (!repeat_body_fixed(node, &m)) return 0;      // refused already; guard
    rxe_lens_rxe(body, L);
    int n = L / m;
    if (L % m || n < node->rep_min) return 0;
    if (node->rep_max != RXE_REP_UNBOUNDED && n > node->rep_max) return 0;
    mpz_t base, zero;
    mpz_init(base);
    lens_at(base, &body->lens, m);
    mpz_init_set_ui(zero, 0);
    struct rep_len_ctx c = { body, s, off, m, n, base, visit, ctx };
    int stop = rep_len_rec(&c, 0, zero);
    mpz_clear(base);
    mpz_clear(zero);
    return stop;
}

// One position's members of exactly length L, each reported by its within-length
// rank. Mirrors seek_node.
static int rank_node_len(struct rxe_node *node, const char *s, int off, int L,
                         rxe_rank_visit visit, void *ctx)
{
    if (node->is_repeat) return rank_repeat_len(node, s, off, L, visit, ctx);
    if (node->rxe)       return rank_at_length(node->rxe, s, off, L, visit, ctx);
    if (node->is_dict) {
        int r = 0, stop = 0;
        for (int k = 0; k < node->nwords && !stop; k++) {
            if ((int)strlen(node->words[k]) != L) continue;
            if (!memcmp(node->words[k], s + off, L)) {
                mpz_t z;
                mpz_init_set_ui(z, r);
                stop = visit(ctx, z);
                mpz_clear(z);
            }
            r++;                           // rank counts length-L words passed
        }
        return stop;
    }
    if (node->len) {
        if (L != 1) return 0;
        for (int i = 0; i < node->len; i++)
            if ((unsigned char)node->str[i] == (unsigned char)s[off]) {
                mpz_t z;
                mpz_init_set_ui(z, i);
                int stop = visit(ctx, z);
                mpz_clear(z);
                if (stop) return 1;
            }
        return 0;
    }
    if (L == 0) {                          // an empty node matches only ""
        mpz_t z;
        mpz_init_set_ui(z, 0);
        int stop = visit(ctx, z);
        mpz_clear(z);
        return stop;
    }
    return 0;
}

// Fold this position's within-length rank qd and the rest's rank r into the
// index: idx = offset(longer splits) + qd*count(rest,L-l) + r. Mirrors the body
// of seek_from.
struct rf_rest {
    rxe_rank_visit visit; void *ctx; mpz_srcptr offset; mpz_srcptr b; mpz_srcptr qd;
};
static int rf_rest_visit(void *v, const mpz_t r)
{
    struct rf_rest *rr = v;
    mpz_t idx;
    mpz_init(idx);
    mpz_mul(idx, rr->qd, rr->b);
    mpz_add(idx, idx, rr->offset);
    mpz_add(idx, idx, r);
    int stop = rr->visit(rr->ctx, idx);
    mpz_clear(idx);
    return stop;
}
struct rf_node {
    struct rxe_node *nxt; const char *s; int roff; int rL;
    rxe_rank_visit visit; void *ctx; mpz_srcptr offset; mpz_srcptr b;
};
static int rf_node_visit(void *v, const mpz_t qd)
{
    struct rf_node *o = v;
    struct rf_rest rr = { o->visit, o->ctx, o->offset, o->b, qd };
    return rank_from(o->nxt, o->s, o->roff, o->rL, rf_rest_visit, &rr);
}

static int rank_from(struct rxe_node *node, const char *s, int off, int L,
                     rxe_rank_visit visit, void *ctx)
{
    if (!node) {
        if (L != 0) return 0;              // length left over: no match
        mpz_t z;
        mpz_init_set_ui(z, 0);
        int stop = visit(ctx, z);
        mpz_clear(z);
        return stop;
    }
    lens_node(node, L);
    lens_rest(node, L);
    mpz_t offset, a, b;
    mpz_init(offset);
    mpz_init(a);
    mpz_init(b);
    // node takes length l, the rest L-l. Longer l are the earlier members, so
    // their blocks are the offset before this split.
    for (int l = 0; l <= L; l++) {
        mpz_set_ui(offset, 0);
        for (int lp = l + 1; lp <= L; lp++) {
            lens_at(a, &node->lens, lp);
            if (!mpz_sgn(a)) continue;
            lens_at(b, &node->rest, L - lp);
            if (!mpz_sgn(b)) continue;
            mpz_addmul(offset, a, b);
        }
        lens_at(b, &node->rest, L - l);    // place value for this position
        struct rf_node o = { node->next, s, off + l, L - l,
                             visit, ctx, offset, b };
        if (rank_node_len(node, s, off, l, rf_node_visit, &o)) {
            mpz_clear(offset);
            mpz_clear(a);
            mpz_clear(b);
            return 1;
        }
    }
    mpz_clear(offset);
    mpz_clear(a);
    mpz_clear(b);
    return 0;
}

// An alternation's members are laid out in order, so an index is that branch's
// start plus the rank within it. Mirrors rxe_seek_at_length.
struct at_ctx { rxe_rank_visit visit; void *ctx; mpz_srcptr base; };
static int at_visit(void *v, const mpz_t j)
{
    struct at_ctx *a = v;
    mpz_t idx;
    mpz_init(idx);
    mpz_add(idx, a->base, j);
    int stop = a->visit(a->ctx, idx);
    mpz_clear(idx);
    return stop;
}
static int rank_at_length(struct rxe *rxe, const char *s, int off, int L,
                          rxe_rank_visit visit, void *ctx)
{
    mpz_t base, c;
    mpz_init_set_ui(base, 0);
    mpz_init(c);
    rxe_lens_rxe(rxe, L);
    for (struct rxe_alt *alt = rxe->head; alt; alt = alt->next) {
        rxe_lens_alt(alt, L);
        lens_at(c, &alt->lens, L);
        if (mpz_sgn(c)) {
            struct at_ctx a = { visit, ctx, base };
            if (rank_from(alt->head, s, off, L, at_visit, &a)) {
                mpz_clear(base);
                mpz_clear(c);
                return 1;
            }
        }
        mpz_add(base, base, c);
    }
    mpz_clear(base);
    mpz_clear(c);
    return 0;
}

// The members shorter than L come first, so their total is the base the
// within-length rank is added to. Mirrors rxe_seek_shortlex.
struct sl_ctx { rxe_rank_visit visit; void *ctx; mpz_srcptr base; };
static int sl_visit(void *v, const mpz_t j)
{
    struct sl_ctx *sl = v;
    mpz_t idx;
    mpz_init(idx);
    mpz_add(idx, sl->base, j);
    int stop = sl->visit(sl->ctx, idx);
    mpz_clear(idx);
    return stop;
}
int rxe_rank_shortlex(struct rxe *rxe, const char *s, int len,
                      rxe_rank_visit visit, void *ctx)
{
    if (!rxe || len < 0 || len > LENS_MAX_LENGTH) return -1;
    if (!shortlex_rankable(rxe, len)) return -1;
    mpz_t base, c;
    mpz_init_set_ui(base, 0);
    mpz_init(c);
    for (int l = 0; l < len; l++) {
        rxe_count_at_length(c, rxe, l);
        mpz_add(base, base, c);
    }
    struct sl_ctx sl = { visit, ctx, base };
    rank_at_length(rxe, s, 0, len, sl_visit, &sl);
    mpz_clear(base);
    mpz_clear(c);
    return 0;
}
