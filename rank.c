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
 * This is the finite, place-value case. An infinite set, a combinatorial
 * {{k}}, a (?~key:) shuffle, a backreference and left-to-right ordering are
 * refused up front by a scan, with a reason a front-end can print, rather than
 * answered wrongly. See rxe_rank_reason().
 */

#include <stdio.h>
#include <string.h>
#include "rxe.h"

/* ------------------------------------------------------------------------- *
 * Feature scan. rank inverts a subset of the tree the enumerator can build;
 * anything outside it is refused before a single character is matched, so a
 * partial walk can never return a wrong count or a missing index.
 * ------------------------------------------------------------------------- */

static const char *g_reason;

static int scan(struct rxe *rxe)
{
    if (!rxe) { g_reason = "null expression"; return 1; }
    if (rxe->flags & RXE_FLAG_LEFT_TO_RIGHT) {
        g_reason = "left-to-right ordering";
        return 1;
    }
    for (struct rxe_alt *alt = rxe->head; alt; alt = alt->next) {
        if (alt->ninf) { g_reason = "infinite set"; return 1; }
        for (struct rxe_node *node = alt->head; node; node = node->next) {
            if (node->is_backref) { g_reason = "backreference"; return 1; }
            if (node->is_comb)    { g_reason = "combinatorial {{k}}"; return 1; }
            if (node->is_inf)     { g_reason = "infinite subexpression"; return 1; }
            if (node->is_repeat && node->rep_max == RXE_REP_UNBOUNDED) {
                g_reason = "unbounded repetition"; return 1;
            }
            // A backreference borrows another group's tree; do not descend into
            // it. Every other subexpression is the node's own to walk.
            if (node->rxe && !node->is_backref && scan(node->rxe)) return 1;
        }
    }
    return 0;
}

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

/* ------------------------------------------------------------------------- *
 * Counting: how many index-paths render a slice, with no index ever built.
 * A set is the sum over its alternations; an alternation is a DP over the split
 * points of its concatenation; a node's own multiplicity closes the recursion.
 * ------------------------------------------------------------------------- */

static void count_rxe(mpz_t out, struct rxe *rxe, const char *s, int len);

// How many members of one node equal exactly s[off..q).
static void count_node(mpz_t out, struct rxe_node *node,
                       const char *s, int off, int q)
{
    int seglen = q - off;
    mpz_set_ui(out, 0);

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

// --- continuing a concatenation: fold this node's match into the running
// index and go on to the next node.
struct seq_cont {
    struct rxe_node *node;
    const char *s;
    int len;
    mpz_ptr acc;
    mpz_ptr place;
    rank_sink sink;
    void *ctx;
};

static int enum_seq(struct rxe_node *node, const char *s, int off, int len,
                    mpz_ptr acc, rank_sink sink, void *ctx);

static int seq_emit(void *v, mpz_srcptr d, int q)
{
    struct seq_cont *c = v;
    mpz_t acc2;
    mpz_init(acc2);
    mpz_mul(acc2, d, c->place);               // index += d * placevalue
    mpz_add(acc2, acc2, c->acc);
    int stop = enum_seq(c->node->next, c->s, q, c->len, acc2, c->sink, c->ctx);
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
// seek decodes. value accumulates the body digits most significant first
// (value = value*base + d), placing the last body least significant, as the
// default right-to-left odometer does. Wherever the count is within range, a
// run ending there is a valid match.
struct rep_walk {
    struct rxe_node *node;
    const char *s;
    int len;
    mpz_srcptr base;                          // body cardinality
    emit_fn emit;
    void *ectx;
};

static int rep_go(struct rep_walk *w, int p, int j, mpz_srcptr value);

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

// Continuation for one body match at a fixed end position q.
struct rep_ext { struct rep_walk *w; int j; mpz_srcptr value; int q; };
static int rep_ext_sink(void *v, mpz_srcptr d)
{
    struct rep_ext *e = v;
    mpz_t nv;
    mpz_init(nv);
    mpz_mul(nv, e->value, e->w->base);        // value = value*base + d
    mpz_add(nv, nv, d);
    int stop = rep_go(e->w, e->q, e->j + 1, nv);
    mpz_clear(nv);
    return stop;
}

static int rep_go(struct rep_walk *w, int p, int j, mpz_srcptr value)
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
        struct rep_ext e = { w, j, value, q };
        if (enum_rxe(node->rxe, w->s + p, q - p, rep_ext_sink, &e)) return 1;
    }
    return 0;
}

static int enum_node(struct rxe_node *node, const char *s, int off, int len,
                     emit_fn emit, void *ectx)
{
    if (node->is_repeat) {
        struct rep_walk w = { node, s, len, node->rxe->nitems, emit, ectx };
        mpz_t z;
        mpz_init_set_ui(z, 0);
        int stop = rep_go(&w, off, 0, z);
        mpz_clear(z);
        return stop;
    }
    if (node->is_shuffle) {                   // a keyed group: remap the index
        for (int q = off; q <= len; q++) {
            struct shuf_bridge b = { emit, ectx, q, node->shuffle };
            if (enum_rxe(node->rxe, s + off, q - off, shuf_sink, &b)) return 1;
        }
        return 0;
    }
    if (node->rxe) {                          // a plain subexpression
        for (int q = off; q <= len; q++) {
            struct sub_bridge b = { emit, ectx, q };
            if (enum_rxe(node->rxe, s + off, q - off, sub_sink, &b)) return 1;
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
                    mpz_ptr acc, rank_sink sink, void *ctx)
{
    if (!node) return off == len ? sink(ctx, acc) : 0;
    mpz_t place;
    mpz_init(place);
    place_after(place, node);
    struct seq_cont c = { node, s, len, acc, place, sink, ctx };
    int stop = enum_node(node, s, off, len, seq_emit, &c);
    mpz_clear(place);
    return stop;
}

static int enum_rxe(struct rxe *rxe, const char *s, int len,
                    rank_sink sink, void *ctx)
{
    if (!rxe) return 0;
    for (struct rxe_alt *alt = rxe->head; alt; alt = alt->next) {
        if (alt->ninf) continue;
        if (!mpz_sgn(alt->nitems)) continue;
        mpz_t acc;
        mpz_init_set(acc, alt->start);
        int stop = enum_seq(alt->head, s, 0, len, acc, sink, ctx);
        mpz_clear(acc);
        if (stop) return 1;
    }
    return 0;
}

/* ------------------------------------------------------------------------- *
 * Public entry points.
 * ------------------------------------------------------------------------- */

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
    if (scan(rxe)) return -1;
    struct min_ctx mc;
    mc.found = 0;
    mpz_init(mc.min);
    enum_rxe(rxe, s, (int)strlen(s), min_sink, &mc);
    int rc = mc.found ? 0 : 1;
    if (mc.found) mpz_set(out, mc.min);
    mpz_clear(mc.min);
    return rc;
}

int rxe_rank_count(struct rxe *rxe, const char *s, mpz_t out)
{
    g_reason = NULL;
    if (scan(rxe)) return -1;
    count_rxe(out, rxe, s, (int)strlen(s));
    return 0;
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
    if (scan(rxe)) return -1;
    struct all_ctx a = { cb, ctx, 0 };
    enum_rxe(rxe, s, (int)strlen(s), all_sink, &a);
    return a.n;
}

const char *rxe_rank_reason(void)
{
    return g_reason ? g_reason : "";
}
