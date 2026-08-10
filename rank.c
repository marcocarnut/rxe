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

/*
 * rank -- the inverse of seek. Where rxe_seek turns an index into the member at
 * it, rank turns a member back into the index (or indices) that render it. It
 * is a whole-string, anchored match: the string must equal a member exactly,
 * not merely begin one. The arithmetic mirrors seek at every node -- an
 * alternation adds its start, a concatenation multiplies by place value, a
 * repetition sums its geometric blocks -- run backwards.
 *
 * A set can carry the same member more than once: a class like [aa], an
 * overlapping alternation like (ab|a)(b|bc), a coincidence between two
 * subroutine calls. So rank is not single-valued at the string level even
 * though seek is a bijection at the index level, and the core is a backtracking
 * matcher that yields every index a string can be reached by. It has two
 * shapes: an enumerator, which builds each index and hands it to a sink (used
 * for the first index and for listing them all), and a DP counter, which tallies
 * them without building any (so a count stays cheap and unbounded even when the
 * list would be astronomical).
 *
 * This handles every finite set: alternation, concatenation, repetition, the
 * combinatorial {{k}} and {{k!}} choices, the (?~key:) shuffle, left-to-right
 * ordering and backreferences. An infinite set is dispatched to the shortlex
 * ranker in lens.c; only what neither can do is refused, with a reason a
 * front-end can print. See rxe_rank_reason().
 */

#include <stdio.h>
#include <string.h>
#include "rxe.h"
#include "lens.h"

static const char *g_reason;

// The cardinality seek divides by at this node: a plain subexpression carries
// its own, a repeat or comb the geometric or binomial sum in nitems.
static void node_card(mpz_t out, struct rxe_node *node)
{
    if (node->rxe && !node->is_repeat && !node->is_comb)
        mpz_set(out, node->rxe->nitems);
    else
        mpz_set(out, node->nitems);
}

// Place value of a node: the product of the cardinalities of every node less
// significant than it. The last node is least significant, so a node's weight
// is the product of those after it -- the divisor seek would peel it with.
static void place_after(mpz_t out, struct rxe_node *node)
{
    mpz_t c;
    mpz_init(c);
    mpz_set_ui(out, 1);
    for (struct rxe_node *m = node->next; m; m = m->next) {
        if (m->is_backref) continue;
        node_card(c, m);
        mpz_mul(out, out, c);
    }
    mpz_clear(c);
}

// Under (?L) the head is the least significant node instead of the tail, so a
// node's place value is the product of those before it rather than after.
static void place_before(mpz_t out, struct rxe_node *node)
{
    mpz_t c;
    mpz_init(c);
    mpz_set_ui(out, 1);
    for (struct rxe_node *m = node->prev; m; m = m->prev) {
        if (m->is_backref) continue;
        node_card(c, m);
        mpz_mul(out, out, c);
    }
    mpz_clear(c);
}

// Backref capture. A group records the substring it matched on the current path
// so a later backreference can compare against it. That substring is the slice
// of the input the group consumed -- the member it rendered is exactly the
// bytes it produced -- so nothing is re-rendered and the group's own state is
// left alone. Each match overwrites the last, so a repeated group's backref
// binds to the final iteration, which is the one rxe's render leaves standing;
// the previous value is saved and put back as the path unwinds. A backref adds
// no index of its own, so none of this touches cardinality or place value.
struct cap_save { const char *str; int len; int set; };
static struct cap_save cap_push(struct rxe *g, const char *str, int len)
{
    struct cap_save old = { g->rank_cap, g->rank_cap_len, g->rank_cap_set };
    g->rank_cap = str;
    g->rank_cap_len = len;
    g->rank_cap_set = 1;
    return old;
}
static void cap_pop(struct rxe *g, struct cap_save old)
{
    g->rank_cap = old.str;
    g->rank_cap_len = old.len;
    g->rank_cap_set = old.set;
}

// Whether any backreference appears in the tree. A backref ties two positions
// together, so the counting DP -- which assumes the nodes are independent --
// cannot be used; such a set is counted by enumeration instead.
static int has_backref(struct rxe *rxe)
{
    if (!rxe) return 0;
    for (struct rxe_alt *alt = rxe->head; alt; alt = alt->next)
        for (struct rxe_node *node = alt->head; node; node = node->next) {
            if (node->is_backref) return 1;
            if (node->rxe && !node->is_backref && has_backref(node->rxe))
                return 1;
        }
    return 0;
}

/* ------------------------------------------------------------------------- *
 * Counting: how many index-paths render a slice, with no index ever built.
 * A set is the sum over its alternations; an alternation is a DP over the split
 * points of its concatenation; a node's own multiplicity closes the recursion.
 * ------------------------------------------------------------------------- */

static void count_rxe(mpz_t out, struct rxe *rxe, const char *s, int len);

// How many combinatorial members equal exactly s[off..q). Defined with the rest
// of the {{k}} machinery below, since it enumerates the valid choices -- their
// indices must be increasing or distinct, a constraint no plain count can see.
static void comb_count(mpz_t out, struct rxe_node *node,
                       const char *s, int off, int q);

// How many members of one node equal exactly s[off..q).
static void count_node(mpz_t out, struct rxe_node *node,
                       const char *s, int off, int q)
{
    int seglen = q - off;
    mpz_set_ui(out, 0);

    if (node->is_comb) { comb_count(out, node, s, off, q); return; }
    if (node->is_repeat) {
        // A run of k copies of the body, k in [rep_min, rep_max]. R[j][pos] is
        // the number of ways the tail from position off+pos is matched by
        // exactly j bodies; the answer sums R[j][0] over the permitted k.
        struct rxe *body = node->rxe;
        int maxk = node->rep_max, mink = node->rep_min;
        // A run cannot hold more non-empty bodies than the slice has
        // characters, so cap the table at the slice length unless the body can
        // itself be empty -- otherwise 'x{0,1000000}' against three characters
        // would size a million-row table to fill three of it. An empty-matching
        // body genuinely reaches a string many ways and keeps the full range.
        mpz_t ec;
        mpz_init(ec);
        count_rxe(ec, body, s + off, 0);
        if (!mpz_sgn(ec) && maxk > seglen) maxk = seglen;
        mpz_clear(ec);
        int np = seglen + 1;
        mpz_t *R = NEW((maxk + 1) * np, mpz_t);
        for (int i = 0; i < (maxk + 1) * np; i++) mpz_init(R[i]);
        for (int pos = 0; pos <= seglen; pos++)
            mpz_set_ui(R[0 * np + pos], pos == seglen);   // 0 bodies: only empty
        mpz_t bc, t;
        mpz_init(bc);
        mpz_init(t);
        for (int j = 1; j <= maxk; j++)
            for (int pos = seglen; pos >= 0; pos--) {
                int p = off + pos;
                mpz_t *cell = &R[j * np + pos];
                for (int r = p; r <= q; r++) {
                    count_rxe(bc, body, s + p, r - p);
                    if (!mpz_sgn(bc)) continue;
                    mpz_mul(t, bc, R[(j - 1) * np + (r - off)]);
                    mpz_add(*cell, *cell, t);
                }
            }
        for (int j = mink; j <= maxk; j++) mpz_add(out, out, R[j * np + 0]);
        mpz_clear(bc);
        mpz_clear(t);
        for (int i = 0; i < (maxk + 1) * np; i++) mpz_clear(R[i]);
        rxe_mem_free(R);
        return;
    }
    if (node->rxe) {                          // a plain subexpression
        count_rxe(out, node->rxe, s + off, seglen);
        return;
    }
    if (node->is_dict) {                      // a whole word
        for (int i = 0; i < node->nwords; i++) {
            const char *w = node->words[i];
            if ((int)strlen(w) == seglen && !memcmp(w, s + off, seglen))
                mpz_add_ui(out, out, 1);
        }
        return;
    }
    if (node->len) {                          // a character class or literal
        if (seglen == 1)
            for (int i = 0; i < node->len; i++)
                if ((unsigned char)node->str[i] == (unsigned char)s[off])
                    mpz_add_ui(out, out, 1);
        return;
    }
    if (seglen == 0) mpz_set_ui(out, 1);      // an empty node matches only ""
}

// How many index-paths let the nodes from `node` to the tail match s[off..len).
static void count_seq(mpz_t out, struct rxe_node *node,
                      const char *s, int off, int len)
{
    if (!node) { mpz_set_ui(out, off == len); return; }
    mpz_set_ui(out, 0);
    mpz_t e, rest, t;
    mpz_init(e);
    mpz_init(rest);
    mpz_init(t);
    for (int q = off; q <= len; q++) {
        count_node(e, node, s, off, q);
        if (!mpz_sgn(e)) continue;
        count_seq(rest, node->next, s, q, len);
        mpz_mul(t, e, rest);
        mpz_add(out, out, t);
    }
    mpz_clear(e);
    mpz_clear(rest);
    mpz_clear(t);
}

static void count_rxe(mpz_t out, struct rxe *rxe, const char *s, int len)
{
    mpz_set_ui(out, 0);
    if (!rxe) return;
    mpz_t t;
    mpz_init(t);
    for (struct rxe_alt *alt = rxe->head; alt; alt = alt->next) {
        if (alt->ninf) continue;
        if (!mpz_sgn(alt->nitems)) continue;   // matches nothing
        count_seq(t, alt->head, s, 0, len);
        mpz_add(out, out, t);
    }
    mpz_clear(t);
}

/* ------------------------------------------------------------------------- *
 * Enumeration: the same walk, building each whole-match index and handing it
 * to a sink. A sink returns non-zero to stop early. Every function returns 1
 * to mean "stop requested, unwind" and 0 to carry on.
 * ------------------------------------------------------------------------- */

typedef int (*rank_sink)(void *ctx, mpz_srcptr idx);

static int enum_rxe(struct rxe *rxe, const char *s, int len,
                    rank_sink sink, void *ctx);

// enum_node calls emit(ectx, d, q) once for each way `node` matches s[off..q),
// d being the node's own index for that match. It threads the string only,
// never the whole assembled index.
typedef int (*emit_fn)(void *ectx, mpz_srcptr d, int q);

// A combinatorial choice reports each of its members through this, the local
// index and the position the member ends at. Defined with the {{k}} code below.
typedef int (*comb_cb)(void *ctx, mpz_srcptr local, int endpos);
static int comb_walk(struct rxe_node *node, const char *s, int off, int len,
                     comb_cb cb, void *ctx);

// Feeding a {{k}} member straight on to the enclosing concatenation's emit.
struct comb_emit_ctx { emit_fn emit; void *ectx; };
static int comb_emit_cb(void *v, mpz_srcptr local, int endpos)
{
    struct comb_emit_ctx *c = v;
    return c->emit(c->ectx, local, endpos);
}

// --- continuing a concatenation: fold this node's match into the running
// index and go on to the next node.
struct seq_cont {
    struct rxe_node *node;
    const char *s;
    int len;
    int l2r;
    mpz_ptr acc;
    mpz_ptr place;
    rank_sink sink;
    void *ctx;
};

static int enum_seq(struct rxe_node *node, const char *s, int off, int len,
                    int l2r, mpz_ptr acc, rank_sink sink, void *ctx);

static int seq_emit(void *v, mpz_srcptr d, int q)
{
    struct seq_cont *c = v;
    mpz_t acc2;
    mpz_init(acc2);
    mpz_mul(acc2, d, c->place);               // index += d * placevalue
    mpz_add(acc2, acc2, c->acc);
    int stop = enum_seq(c->node->next, c->s, q, c->len, c->l2r, acc2,
                        c->sink, c->ctx);
    mpz_clear(acc2);
    return stop;
}

// --- one member of a subexpression, ending at q, is one match of the node.
struct sub_bridge { emit_fn emit; void *ectx; int q; };
static int sub_sink(void *v, mpz_srcptr d)
{
    struct sub_bridge *b = v;
    return b->emit(b->ectx, d, b->q);
}

// --- a shuffled group. The key reorders which member sits at which index, so
// the member found in the underlying set at index u is presented at unmap(u).
// The count is untouched -- a permutation is a bijection, so a string is
// reached by exactly as many indices either way -- only the index is remapped.
struct shuf_bridge { emit_fn emit; void *ectx; int q; struct rxe_permutation *p; };
static int shuf_sink(void *v, mpz_srcptr u)
{
    struct shuf_bridge *b = v;
    mpz_t pos;
    mpz_init(pos);
    rxe_permutation_unmap(pos, b->p, u);
    int stop = b->emit(b->ectx, pos, b->q);
    mpz_clear(pos);
    return stop;
}

// --- repetition. Walk the body 0..k times, building the block-and-digit index
// seek decodes. By default the last body is the least significant digit, so
// value accumulates most significant first (value = value*base + d); under
// (?L) the first body is least significant, so each body is added at a running
// weight instead (value += d*weight, weight *= base). Wherever the count is
// within range, a run ending there is a valid match.
struct rep_walk {
    struct rxe_node *node;
    const char *s;
    int len;
    int l2r;
    mpz_srcptr base;                          // body cardinality
    emit_fn emit;
    void *ectx;
};

static int rep_go(struct rep_walk *w, int p, int j,
                  mpz_srcptr value, mpz_srcptr weight);

// Sum of base^m for m in [mink, k): the indices the shorter runs occupy before
// this one.
static void block_offset(mpz_t out, mpz_srcptr base, int mink, int k)
{
    mpz_t p;
    mpz_init(p);
    mpz_pow_ui(p, base, mink);
    mpz_set_ui(out, 0);
    for (int m = mink; m < k; m++) {
        mpz_add(out, out, p);
        mpz_mul(p, p, base);
    }
    mpz_clear(p);
}

// Continuation for one body match over [start, q).
struct rep_ext {
    struct rep_walk *w; int j; mpz_srcptr value; mpz_srcptr weight;
    int start; int q;
};
static int rep_ext_sink(void *v, mpz_srcptr d)
{
    struct rep_ext *e = v;
    mpz_t nv, nw;
    mpz_init(nv);
    mpz_init(nw);
    if (e->w->l2r) {
        mpz_mul(nv, d, e->weight);            // value += d * weight
        mpz_add(nv, nv, e->value);
        mpz_mul(nw, e->weight, e->w->base);   // weight *= base
    } else {
        mpz_mul(nv, e->value, e->w->base);    // value = value*base + d
        mpz_add(nv, nv, d);
        mpz_set(nw, e->weight);               // weight unused, carried along
    }
    // Bind a backref into this repeated group to the latest iteration's text,
    // the one rxe's render leaves standing; each iteration overwrites the last.
    struct cap_save sv = cap_push(e->w->node->rxe, e->w->s + e->start,
                                  e->q - e->start);
    int stop = rep_go(e->w, e->q, e->j + 1, nv, nw);
    cap_pop(e->w->node->rxe, sv);
    mpz_clear(nv);
    mpz_clear(nw);
    return stop;
}

static int rep_go(struct rep_walk *w, int p, int j,
                  mpz_srcptr value, mpz_srcptr weight)
{
    struct rxe_node *node = w->node;
    if (j >= node->rep_min && j <= node->rep_max) {
        mpz_t local, off;
        mpz_init(local);
        mpz_init(off);
        block_offset(off, w->base, node->rep_min, j);
        mpz_add(local, off, value);
        int stop = w->emit(w->ectx, local, p);
        mpz_clear(local);
        mpz_clear(off);
        if (stop) return 1;
    }
    if (j >= node->rep_max) return 0;
    for (int q = p; q <= w->len; q++) {
        struct rep_ext e = { w, j, value, weight, p, q };
        if (enum_rxe(node->rxe, w->s + p, q - p, rep_ext_sink, &e)) return 1;
    }
    return 0;
}

static int enum_node(struct rxe_node *node, const char *s, int off, int len,
                     int l2r, emit_fn emit, void *ectx)
{
    if (node->is_backref) {                   // must equal what its group matched
        struct rxe *g = node->rxe;
        int L = g->rank_cap_len;
        if (!g->rank_cap_set) return 0;       // group not yet bound: no match
        if (off + L > len || memcmp(g->rank_cap, s + off, L)) return 0;
        mpz_t z;
        mpz_init_set_ui(z, 0);                 // a backref carries no index
        int stop = emit(ectx, z, off + L);
        mpz_clear(z);
        return stop;
    }
    if (node->is_repeat) {
        struct rep_walk w = { node, s, len, l2r, node->rxe->nitems, emit, ectx };
        mpz_t z, one;
        mpz_init_set_ui(z, 0);
        mpz_init_set_ui(one, 1);              // the first body's weight, under (?L)
        int stop = rep_go(&w, off, 0, z, one);
        mpz_clear(z);
        mpz_clear(one);
        return stop;
    }
    if (node->is_comb) {                      // a {{k}} choice
        struct comb_emit_ctx c = { emit, ectx };
        return comb_walk(node, s, off, len, comb_emit_cb, &c);
    }
    if (node->is_shuffle) {                   // a keyed group: remap the index
        for (int q = off; q <= len; q++) {
            struct shuf_bridge b = { emit, ectx, q, node->shuffle };
            struct cap_save sv = cap_push(node->rxe, s + off, q - off);
            int stop = enum_rxe(node->rxe, s + off, q - off, shuf_sink, &b);
            cap_pop(node->rxe, sv);
            if (stop) return 1;
        }
        return 0;
    }
    if (node->rxe) {                          // a plain subexpression
        for (int q = off; q <= len; q++) {
            struct sub_bridge b = { emit, ectx, q };
            // Record what this group matched over [off,q), for any backref to it.
            struct cap_save sv = cap_push(node->rxe, s + off, q - off);
            int stop = enum_rxe(node->rxe, s + off, q - off, sub_sink, &b);
            cap_pop(node->rxe, sv);
            if (stop) return 1;
        }
        return 0;
    }
    if (node->is_dict) {                      // a whole word
        for (int i = 0; i < node->nwords; i++) {
            const char *w = node->words[i];
            int wl = (int)strlen(w);
            if (off + wl > len || memcmp(w, s + off, wl)) continue;
            mpz_t d;
            mpz_init_set_ui(d, i);
            int stop = emit(ectx, d, off + wl);
            mpz_clear(d);
            if (stop) return 1;
        }
        return 0;
    }
    if (node->len) {                          // a character class or literal
        if (off < len)
            for (int i = 0; i < node->len; i++)
                if ((unsigned char)node->str[i] == (unsigned char)s[off]) {
                    mpz_t d;
                    mpz_init_set_ui(d, i);
                    int stop = emit(ectx, d, off + 1);
                    mpz_clear(d);
                    if (stop) return 1;
                }
        return 0;
    }
    // An empty node matches only the empty string, contributing index 0.
    mpz_t z;
    mpz_init_set_ui(z, 0);
    int stop = emit(ectx, z, off);
    mpz_clear(z);
    return stop;
}

static int enum_seq(struct rxe_node *node, const char *s, int off, int len,
                    int l2r, mpz_ptr acc, rank_sink sink, void *ctx)
{
    if (!node) return off == len ? sink(ctx, acc) : 0;
    mpz_t place;
    mpz_init(place);
    if (l2r) place_before(place, node);
    else     place_after(place, node);
    struct seq_cont c = { node, s, len, l2r, acc, place, sink, ctx };
    int stop = enum_node(node, s, off, len, l2r, seq_emit, &c);
    mpz_clear(place);
    return stop;
}

static int enum_rxe(struct rxe *rxe, const char *s, int len,
                    rank_sink sink, void *ctx)
{
    if (!rxe) return 0;
    int l2r = (rxe->flags & RXE_FLAG_LEFT_TO_RIGHT) != 0;
    for (struct rxe_alt *alt = rxe->head; alt; alt = alt->next) {
        if (alt->ninf) continue;
        if (!mpz_sgn(alt->nitems)) continue;
        mpz_t acc;
        mpz_init_set(acc, alt->start);
        int stop = enum_seq(alt->head, s, 0, len, l2r, acc, sink, ctx);
        mpz_clear(acc);
        if (stop) return 1;
    }
    return 0;
}

/* ------------------------------------------------------------------------- *
 * Combinatorial choice, {{k}} and {{k!}}. seek decodes an index into a choice
 * of body members through the combinatorial or factorial number system; rank
 * encodes a choice back. The wrinkle is that the members come as a string, not
 * as indices, so the choice has to be recovered first: split the string into
 * body members, and keep only the splits whose indices form a valid choice --
 * strictly increasing for an unordered {{k}}, all distinct for an ordered
 * {{k!}}. Each valid choice is one index; several may spell one string, and
 * those are its duplicates.
 * ------------------------------------------------------------------------- */

// Members of one size: C(n,k) unordered, or P(n,k)=C(n,k)k! ordered.
static void rk_size_count(mpz_t out, mpz_srcptr n, int size, int perm)
{
    mpz_bin_ui(out, n, (unsigned long)size);
    if (perm && size > 1) {
        mpz_t f;
        mpz_init(f);
        mpz_fac_ui(f, (unsigned long)size);
        mpz_mul(out, out, f);
        mpz_clear(f);
    }
}

// The index a run of this size starts at: every shorter size laid before it.
static void comb_block_offset(mpz_t out, mpz_srcptr n, int lo, int size, int perm)
{
    mpz_t c;
    mpz_init(c);
    mpz_set_ui(out, 0);
    for (int s = lo; s < size; s++) {
        rk_size_count(c, n, s, perm);
        mpz_add(out, out, c);
    }
    mpz_clear(c);
}

// The inverse of decode_comb: the combinadic j = sum C(chosen[i], i+1), the
// chosen indices ascending. (comb.c's decode reads this same sum backwards.)
static void encode_comb(mpz_t out, mpz_t *chosen, int size)
{
    mpz_t c;
    mpz_init(c);
    mpz_set_ui(out, 0);
    for (int i = 0; i < size; i++) {
        mpz_bin_ui(c, chosen[i], (unsigned long)(i + 1));
        mpz_add(out, out, c);
    }
    mpz_clear(c);
}

// The inverse of decode_perm: the factorial-base numeral whose digit at each
// position is that member's rank among the ones not yet used, times the falling
// factorial of the positions still to fill -- the Lehmer code.
static void encode_perm(mpz_t out, mpz_t *chosen, int size, mpz_srcptr n)
{
    mpz_t block, rank, term, rest;
    mpz_init(block);
    mpz_init(rank);
    mpz_init(term);
    mpz_init(rest);
    mpz_set_ui(out, 0);
    for (int p = 0; p < size; p++) {
        mpz_sub_ui(rest, n, (unsigned long)(p + 1));     // n-1-p
        mpz_set_ui(block, 1);
        for (int t = 0; t < size - 1 - p; t++) {
            mpz_sub_ui(term, rest, (unsigned long)t);
            mpz_mul(block, block, term);
        }
        mpz_set(rank, chosen[p]);                        // rank among the unused
        for (int i = 0; i < p; i++)
            if (mpz_cmp(chosen[i], chosen[p]) < 0) mpz_sub_ui(rank, rank, 1);
        mpz_mul(term, rank, block);
        mpz_add(out, out, term);
    }
    mpz_clear(block);
    mpz_clear(rank);
    mpz_clear(term);
    mpz_clear(rest);
}

// Walking the choices. chosen[] holds the body indices picked so far; at each
// depth in [lo,hi] the run is a valid member and its index is reported.
struct comb_state {
    struct rxe_node *node;
    const char *s;
    int len, lo, hi, perm;
    mpz_srcptr n;                 // body cardinality
    mpz_t *chosen;
    comb_cb cb;
    void *ctx;
};

static int comb_rec(struct comb_state *st, int pos, int depth);

// One more body match, at index d over some prefix: admit it only if it keeps
// the choice valid, then descend.
struct comb_body { struct comb_state *st; int q; int depth; };
static int comb_body_sink(void *v, mpz_srcptr d)
{
    struct comb_body *b = v;
    struct comb_state *st = b->st;
    int depth = b->depth;
    if (st->perm) {                           // ordered: all distinct
        for (int i = 0; i < depth; i++)
            if (!mpz_cmp(st->chosen[i], d)) return 0;
    } else {                                  // unordered: strictly increasing
        if (depth > 0 && mpz_cmp(d, st->chosen[depth - 1]) <= 0) return 0;
    }
    mpz_set(st->chosen[depth], d);
    return comb_rec(st, b->q, depth + 1);
}

static int comb_rec(struct comb_state *st, int pos, int depth)
{
    if (depth >= st->lo && depth <= st->hi) {
        mpz_t local, off, enc;
        mpz_init(local);
        mpz_init(off);
        mpz_init(enc);
        comb_block_offset(off, st->n, st->lo, depth, st->perm);
        if (st->perm) encode_perm(enc, st->chosen, depth, st->n);
        else          encode_comb(enc, st->chosen, depth);
        mpz_add(local, off, enc);
        int stop = st->cb(st->ctx, local, pos);
        mpz_clear(local);
        mpz_clear(off);
        mpz_clear(enc);
        if (stop) return 1;
    }
    if (depth >= st->hi) return 0;
    for (int q = pos; q <= st->len; q++) {
        struct comb_body b = { st, q, depth };
        if (enum_rxe(st->node->rxe, st->s + pos, q - pos, comb_body_sink, &b))
            return 1;
    }
    return 0;
}

static int comb_walk(struct rxe_node *node, const char *s, int off, int len,
                     comb_cb cb, void *ctx)
{
    int hi = node->rep_max, n = hi > 0 ? hi : 1;
    struct comb_state st = {
        node, s, len, node->rep_min, hi, node->comb_perm,
        node->rxe->nitems, NEW(n, mpz_t), cb, ctx
    };
    for (int i = 0; i < n; i++) mpz_init(st.chosen[i]);
    int stop = comb_rec(&st, off, 0);
    for (int i = 0; i < n; i++) mpz_clear(st.chosen[i]);
    rxe_mem_free(st.chosen);
    return stop;
}

// Count is the choices that consume exactly s[off..q); a choice ending short of
// q fills a smaller segment and belongs to another split, so it is not counted
// here. Each valid choice is one index, so counting them is counting indices.
struct comb_count_ctx { int q; mpz_ptr out; };
static int comb_count_cb(void *v, mpz_srcptr local, int endpos)
{
    struct comb_count_ctx *c = v;
    if (endpos == c->q) mpz_add_ui(c->out, c->out, 1);
    return 0;
}

static void comb_count(mpz_t out, struct rxe_node *node,
                       const char *s, int off, int q)
{
    mpz_set_ui(out, 0);
    struct comb_count_ctx c = { q, out };
    comb_walk(node, s, off, q, comb_count_cb, &c);
}

/* ------------------------------------------------------------------------- *
 * Public entry points.
 * ------------------------------------------------------------------------- */

// Walk the set for the string, handing each index it sits at to the sink.
// Returns 0 on success, -1 when the set is one rank cannot handle (g_reason
// says why). A finite set goes to the place-value enumerator; a shortlex
// infinite set to the length-indexed ranker in lens.c; a non-shortlex infinite
// set -- a backreference that keeps an infinite set in diagonal order -- is
// refused, as is a shortlex set the ranker does not cover yet.
static int rank_walk(struct rxe *rxe, const char *s, rank_sink sink, void *ctx)
{
    if (!rxe) { g_reason = "null expression"; return -1; }
    if (rxe_is_infinite(rxe)) {
        if (!rxe_is_shortlex(rxe)) {
            g_reason = "infinite set kept in diagonal order by a backreference";
            return -1;
        }
        if (rxe_rank_shortlex(rxe, s, (int)strlen(s),
                              (rxe_rank_visit)sink, ctx) < 0) {
            g_reason = "infinite set with a variable-length body or (?L)";
            return -1;
        }
        return 0;
    }
    enum_rxe(rxe, s, (int)strlen(s), sink, ctx);
    return 0;
}

// First (smallest) index, tracked without stopping so the result is the least
// of the several a duplicate may sit at, not merely the first walked to.
struct min_ctx { int found; mpz_t min; };
static int min_sink(void *v, mpz_srcptr idx)
{
    struct min_ctx *m = v;
    if (!m->found || mpz_cmp(idx, m->min) < 0) {
        mpz_set(m->min, idx);
        m->found = 1;
    }
    return 0;
}

int rxe_rank(struct rxe *rxe, const char *s, mpz_t out)
{
    g_reason = NULL;
    struct min_ctx mc;
    mc.found = 0;
    mpz_init(mc.min);
    if (rank_walk(rxe, s, min_sink, &mc) < 0) { mpz_clear(mc.min); return -1; }
    int rc = mc.found ? 0 : 1;
    if (mc.found) mpz_set(out, mc.min);
    mpz_clear(mc.min);
    return rc;
}

// Counting a set the enumerator has to walk -- a backreference breaks the DP's
// independence, and an infinite set has no DP at all -- by tallying what the
// walk visits. Both are finite for a given string and usually spelt few ways,
// so this is affordable; it just is not the cap-free count the DP gives.
static int tally_sink(void *v, mpz_srcptr idx)
{
    (void)idx;
    mpz_add_ui((mpz_ptr)v, (mpz_ptr)v, 1);
    return 0;
}

int rxe_rank_count(struct rxe *rxe, const char *s, mpz_t out)
{
    g_reason = NULL;
    if (rxe && !rxe_is_infinite(rxe) && !has_backref(rxe)) {
        count_rxe(out, rxe, s, (int)strlen(s));   // the cheap, cap-free DP
        return 0;
    }
    mpz_set_ui(out, 0);
    return rank_walk(rxe, s, tally_sink, out);     // -1 refused, 0 ok
}

struct all_ctx { rxe_rank_cb cb; void *ctx; long n; };
static int all_sink(void *v, mpz_srcptr idx)
{
    struct all_ctx *a = v;
    a->n++;
    return a->cb ? a->cb(idx, a->ctx) : 0;
}

long rxe_rank_all(struct rxe *rxe, const char *s, rxe_rank_cb cb, void *ctx)
{
    g_reason = NULL;
    struct all_ctx a = { cb, ctx, 0 };
    if (rank_walk(rxe, s, all_sink, &a) < 0) return -1;
    return a.n;
}

const char *rxe_rank_reason(void)
{
    return g_reason ? g_reason : "";
}
