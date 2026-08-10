/*
 * graph.c - the parse-tree walk behind rxe_graph.h.
 *
 * This is rxedot's old tree-walk, lifted whole into the library so that every
 * client draws the same tree the same way. Where rxedot used to fprintf a line
 * of DOT, the walk now calls a visitor callback with the same information,
 * computed identically and in the same order. The DOT backend that remains in
 * rxedot turns those calls back into the exact bytes it printed before; the
 * browser's binding turns them into JSON. Nothing here knows about either.
 *
 * This program is free software under the GNU General Public License v2 or
 * later; see http://www.gnu.org/licenses/gpl-2.0.html.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmp.h>
#include "rxe.h"
#include "rxe_graph.h"
#include "lens.h"    // rxe_seek_at_length, for rendering a lit repeat's text

// The walk's running state: the visitor to drive, the next node id (sequential,
// so ids match rxedot's old counter), the caller's options and the root source
// text, and a table mapping each group's rxe to the id of the box that stands
// for it, so a backreference can point an edge back to the real thing.
struct walk {
    const struct rxe_graph_visitor *v;
    void       *ctx;
    const struct rxe_graph_opts    *opts;
    struct rxe *root;
    const char *source;
    int         idc;
    struct { struct rxe *rxe; int id; } gmap[8192];
    int         gmapn;
};

static void map_put(struct walk *w, struct rxe *r, int id) {
    if (w->gmapn < (int)(sizeof w->gmap / sizeof *w->gmap)) {
        w->gmap[w->gmapn].rxe = r; w->gmap[w->gmapn].id = id; w->gmapn++;
    }
}
static int map_get(struct walk *w, struct rxe *r) {
    for (int i = 0; i < w->gmapn; i++) if (w->gmap[i].rxe == r) return w->gmap[i].id;
    return -1;
}

// A cardinality, short enough to fit in a box: the exact number up to fifteen
// digits, an order-of-magnitude sketch beyond, and the infinity sign when the
// set has no largest member.
static void gnum(char *b, size_t n, const mpz_t v, int inf) {
    if (inf) { snprintf(b, n, "∞"); return; }
    char *s = mpz_get_str(NULL, 10, v);
    size_t len = strlen(s);
    if (len <= 15) snprintf(b, n, "%s", s);
    else snprintf(b, n, "~%c.%c%c%ce%zu", s[0], s[1], s[2], s[3], len - 1);
    free(s);
}

// The exact cardinality as a decimal, when it is short enough to show in full
// (up to 60 digits, which fits a 64-byte buffer); otherwise "", and the client
// falls back to the abbreviated form. An infinite node yields "" too. This is
// what lets the browser group a number with thousand separators rather than
// show the order-of-magnitude sketch gnum draws for a cramped DOT box.
static void gexact(char *b, size_t n, const mpz_t v, int inf) {
    if (inf || mpz_sizeinbase(v, 10) > 60 || n < 64) { b[0] = 0; return; }
    mpz_get_str(b, 10, v);
}

// The text a node contributes to the current member -- what rxe_current would
// print for it -- capped, for showing a lit node's own output. The tree is
// already seeked, so this reads the state a prior rxe_seek left. Empty stays
// empty; the caller shows a placeholder for it.
static void node_text(char *b, size_t n, struct walk *w, struct rxe_node *node) {
    int shortlex = w->root && (w->root->flags & RXE_FLAG_SHORTLEX);
    char *end = b;      // rxe_current writes up to (maxlen) chars then a null, so
    b[0] = 0;           // it is always handed (bytes left) - 1.
    if (node->is_repeat || node->is_comb) {
        for (int i = 0; i < node->rep_count && i < node->rep_alloc; i++) {
            size_t left = n - (size_t)(end - b);
            if (left <= 1) break;
            if (shortlex ? rxe_seek_at_length(node->rxe, node->rep_len[i], node->rep_digit[i])
                         : rxe_seek(node->rxe, node->rep_digit[i])) break;
            end = rxe_current(end, (int)left - 1, node->rxe);
        }
    } else if (node->rxe) {
        end = rxe_current(end, (int)n - 1, node->rxe);
    } else if (node->is_dict) {
        const char *word = node->words[node->iterator];
        while (*word && (size_t)(end - b) + 1 < n) *end++ = *word++;
    } else if (node->len) {
        if (n > 1) *end++ = node->str[node->iterator];
    }
    *end = 0;
}

// A node's exact input text, read from its source span.
static void node_source(char *b, size_t n, struct walk *w, struct rxe_node *node) {
    int a = node->src_start, e = node->src_end;
    if (!w->source || e <= a || a < 0) { b[0] = 0; return; }
    size_t len = (size_t)(e - a);
    if (len >= n) len = n - 1;
    memcpy(b, w->source + a, len);
    b[len] = 0;
}

// The pieces a fixed repetition's iterations produced under a lit path,
// space-joined and capped, read by pointing the body at each stored index.
static void repeat_choices(struct rxe_node *node, char *b, size_t n) {
    b[0] = 0;
    size_t p = 0;
    for (int i = 0; i < node->rep_count && i < 24; i++) {
        char piece[128];
        rxe_seek(node->rxe, node->rep_digit[i]);
        rxe_current(piece, sizeof piece - 1, node->rxe);
        p += snprintf(b + p, p < n ? n - p : 0, "%s%s", i ? " " : "→ ", piece);
        if (p >= n - 12) break;
    }
    if (node->rep_count > 24 && p < n - 3)
        snprintf(b + p, n - p, " …");
}

// A concatenation node's place value: the product of the sizes of its less
// significant siblings -- those after it, or before it under (?L). Left at 1
// for the least significant, or for any endless concatenation.
static void concat_weight(struct rxe_alt *a, struct rxe_node *nd, mpz_t w) {
    mpz_set_ui(w, 1);
    int l2r = a->owner && (a->owner->flags & RXE_FLAG_LEFT_TO_RIGHT);
    for (struct rxe_node *m = a->head; m; m = m->next) if (m->is_inf) return;
    for (struct rxe_node *m = l2r ? nd->prev : nd->next; m;
         m = l2r ? m->prev : m->next)
        mpz_mul(w, w, m->nitems);
}

// A fixed single character: a plain leaf of exactly one member, with a span to
// read it from. A run of these is a literal word, and reads better whole.
static int is_lit(struct rxe_node *n) {
    return n && !n->rxe && !n->is_backref && !n->is_repeat && !n->is_comb
        && !n->is_shuffle && !n->is_dict && !n->refers_to
        && n->src_end > n->src_start && mpz_cmp_ui(n->nitems, 1) == 0;
}

static void draw_contents(struct walk *w, int parent, struct rxe *rxe, int onpath);

// One node for a run of literals from 'first' to 'last', labelled with the
// stretch of source they span -- 'cat' rather than three boxes 'c' 'a' 't'.
static int draw_literal_run(struct walk *w, struct rxe_node *first,
                            struct rxe_node *last, int onpath) {
    int id = w->idc++;
    char src[256];
    int a = first->src_start, e = last->src_end, len = e - a;
    if (len < 0) len = 0;
    if ((size_t)len >= sizeof src) len = sizeof src - 1;
    memcpy(src, w->source + a, len);
    src[len] = 0;
    struct rxe_gnode_ev ev = { 0 };
    ev.id = id; ev.kind = RXE_G_LITERAL; ev.line1 = src; ev.card = "1";
    ev.card_exact = "1"; ev.on_path = onpath; ev.ref_to = -1;
    w->v->node(w->ctx, &ev);
    // Optionally hand over the word's own letters as child leaves, each with
    // its own source span, so a drawing can unfold the word into them. rxedot
    // never asks, so its output is untouched (and the ids these consume are
    // never assigned for it either).
    if (w->opts->letters) {
        for (struct rxe_node *n = first; ; n = n->next) {
            char csrc[64];
            node_source(csrc, sizeof csrc, w, n);
            int cid = w->idc++;
            struct rxe_gnode_ev cev = { 0 };
            cev.id = cid; cev.kind = RXE_G_LEAF; cev.line1 = csrc; cev.card = "1";
            cev.card_exact = "1"; cev.on_path = onpath; cev.ref_to = -1;
            w->v->node(w->ctx, &cev);
            struct rxe_gedge_ev ce = { 0 };
            ce.from = id; ce.from_port = -1; ce.to = cid; ce.on_path = onpath;
            w->v->edge(w->ctx, &ce);
            if (n == last) break;
        }
    }
    return id;
}

// Draw one node of a concatenation and return its id. Leaves are labelled with
// their exact source text; structural nodes carry their kind and their children
// the rest. 'weight' is the place value string, or NULL.
static int draw_node(struct walk *w, struct rxe_node *node, const char *weight,
                     const char *weight_exact, int onpath) {
    int id = w->idc++;
    char line1[256], card[64], cardx[64], src[220], choices[200], text[128];
    choices[0] = 0; text[0] = 0;
    node_source(src, sizeof src, w, node);
    int have_src = src[0] != 0;
    int inf = node->is_inf, recurse = 0, ref_to = -1, unroll = 0;
    enum rxe_gkind kind;

    if (node->refers_to) {                        // a (?N) subroutine call
        snprintf(line1, sizeof line1, "%s", have_src ? src : "(?…)");
        kind = RXE_G_SUBROUTINE;
        if (w->opts->collapse) ref_to = map_get(w, node->refers_to);
        else recurse = 1;
    }
    else if (node->is_backref) {                  // a \N backreference
        snprintf(line1, sizeof line1, "%s", have_src ? src : "\\ref");
        kind = RXE_G_BACKREF;
        ref_to = node->rxe ? map_get(w, node->rxe) : -1;
    }
    else if (node->is_repeat) {
        if (node->rep_max == RXE_REP_UNBOUNDED)
            snprintf(line1, sizeof line1, "repeat {%d,}", node->rep_min);
        else if (node->rep_min == node->rep_max)
            snprintf(line1, sizeof line1, "repeat {%d}", node->rep_min);
        else snprintf(line1, sizeof line1, "repeat {%d,%d}", node->rep_min, node->rep_max);
        kind = RXE_G_REPEAT;
        int fixed = !node->is_inf && node->rep_max != RXE_REP_UNBOUNDED
                    && node->rep_min == node->rep_max;
        if (fixed && node->rep_max >= 1 && node->rep_max <= w->opts->unroll)
            unroll = node->rep_max;
        else {
            recurse = 1;
            if (onpath && fixed && node->rep_count >= 1)
                repeat_choices(node, choices, sizeof choices);
        }
    }
    else if (node->is_comb) {
        const char *verb = node->comb_perm ? "permute" : "choose";
        const char *bang = node->comb_perm ? "!" : "";
        if (node->rep_min == node->rep_max)
            snprintf(line1, sizeof line1, "%s {{%d%s}}", verb, node->rep_min, bang);
        else snprintf(line1, sizeof line1, "%s {{%d,%d%s}}", verb,
                      node->rep_min, node->rep_max, bang);
        kind = RXE_G_COMB; recurse = 1;
    }
    else if (node->is_shuffle) { snprintf(line1, sizeof line1, "shuffle (?~…)"); kind = RXE_G_SHUFFLE; recurse = 1; }
    else if (node->is_dict)    { snprintf(line1, sizeof line1, "%s", have_src ? src : "dict"); kind = RXE_G_DICT; }
    else if (node->rxe)        { snprintf(line1, sizeof line1, "( )"); kind = RXE_G_GROUP; recurse = 1; }
    else { snprintf(line1, sizeof line1, "%s", have_src ? src : "?"); kind = RXE_G_LEAF; }

    gnum(card, sizeof card, node->nitems, inf);
    gexact(cardx, sizeof cardx, node->nitems, inf);
    if (onpath) node_text(text, sizeof text, w, node);

    struct rxe_gnode_ev ev = { 0 };
    ev.id = id; ev.kind = kind; ev.line1 = line1; ev.card = card;
    ev.card_exact = cardx;
    ev.is_inf = inf; ev.place = weight; ev.place_exact = weight_exact;
    ev.choices = choices[0] ? choices : NULL;
    ev.text = onpath ? text : NULL;
    ev.on_path = onpath; ev.ref_to = ref_to;
    ev.rep_min = node->rep_min; ev.rep_max = node->rep_max;
    ev.comb_perm = node->comb_perm;
    w->v->node(w->ctx, &ev);

    if (unroll) {
        for (int i = 0; i < unroll; i++) {
            if (onpath && i < node->rep_count) rxe_seek(node->rxe, node->rep_digit[i]);
            draw_contents(w, id, node->rxe, onpath);
        }
    } else if (recurse && node->rxe) {
        draw_contents(w, id, node->rxe, onpath);
    }
    if (ref_to >= 0) {
        struct rxe_gedge_ev e = { 0 };
        e.from = id; e.from_port = -1; e.to = ref_to; e.is_ref = 1;
        w->v->edge(w->ctx, &e);
    }
    return id;
}

// Draw one alternative's concatenation, hanging from a node id (and, off an
// alternation, a subsection port), folding literal runs and tagging each
// carrying digit with its place value. 'blabel' is the branch's "start / +size"
// for the edges, or NULL when this is not a branch of an alternation.
static void draw_seq(struct walk *w, int from, int from_port, struct rxe_alt *a,
                     int onpath, const char *blabel) {
    mpz_t wt;
    mpz_init(wt);
    for (struct rxe_node *nd = a->head; nd; ) {
        int nid;
        if (w->opts->fold && is_lit(nd) && is_lit(nd->next)) {
            struct rxe_node *last = nd;
            while (is_lit(last->next)) last = last->next;
            nid = draw_literal_run(w, nd, last, onpath);
            nd = last->next;
        } else {
            char wbuf[48], wexact[64];
            const char *wp = NULL, *wpx = NULL;
            if (mpz_cmp_ui(nd->nitems, 1) > 0) {
                concat_weight(a, nd, wt);
                if (mpz_cmp_ui(wt, 1) > 0) {
                    char ws[40];
                    gnum(ws, sizeof ws, wt, 0);
                    snprintf(wbuf, sizeof wbuf, "×%s", ws);
                    wp = wbuf;
                    gexact(wexact, sizeof wexact, wt, 0);
                    wpx = wexact[0] ? wexact : NULL;
                }
            }
            nid = draw_node(w, nd, wp, wpx, onpath);
            nd = nd->next;
        }
        struct rxe_gedge_ev e = { 0 };
        e.from = from; e.from_port = from_port; e.to = nid;
        e.on_path = onpath; e.label = blabel;
        w->v->edge(w->ctx, &e);
    }
    mpz_clear(wt);
}

// Hang the alternations of 'rxe' under 'parent'. One alternative is a plain
// concatenation drawn straight under it. Several become an alternation node --
// one subsection per branch, each labelled with where it starts and how many it
// holds -- with a branch drawn from each subsection's port.
static void draw_contents(struct walk *w, int parent, struct rxe *rxe, int onpath) {
    map_put(w, rxe, parent);
    if (rxe->nalts <= 1) {
        if (rxe->head) draw_seq(w, parent, -1, rxe->head, onpath, NULL);
        return;
    }
    int aid = w->idc++;
    int nsub = rxe->nalts;
    struct rxe_gsub *subs = malloc(nsub * sizeof *subs);
    char (*sbuf)[64] = malloc(nsub * sizeof *sbuf);
    char (*cbuf)[64] = malloc(nsub * sizeof *cbuf);
    char (*sxbuf)[64] = malloc(nsub * sizeof *sxbuf);
    char (*cxbuf)[64] = malloc(nsub * sizeof *cxbuf);
    int k = 0;
    for (struct rxe_alt *a = rxe->head; a; a = a->next, k++) {
        gnum(sbuf[k], sizeof sbuf[k], a->start, 0);
        gnum(cbuf[k], sizeof cbuf[k], a->nitems, a->ninf > 0);
        gexact(sxbuf[k], sizeof sxbuf[k], a->start, 0);
        gexact(cxbuf[k], sizeof cxbuf[k], a->nitems, a->ninf > 0);
        subs[k].start = sbuf[k]; subs[k].card = cbuf[k]; subs[k].is_inf = a->ninf > 0;
        subs[k].start_exact = sxbuf[k]; subs[k].card_exact = cxbuf[k];
    }
    struct rxe_galt_ev aev = { 0 };
    aev.id = aid; aev.on_path = onpath; aev.nsub = nsub; aev.subs = subs;
    w->v->alt(w->ctx, &aev);

    struct rxe_gedge_ev pe = { 0 };
    pe.from = parent; pe.from_port = -1; pe.to = aid; pe.on_path = onpath;
    w->v->edge(w->ctx, &pe);

    // Branch zero is drawn last under alt_reverse, so dagre (which keeps the
    // insertion order of a crossing-free fan) leaves it rightmost -- the browser
    // wants a lit path to read in written order. Either way each branch keeps
    // its own index k, so its port and its "start / +size" label stay right.
    int rev = w->opts->alt_reverse;
    struct rxe_alt *a = rev ? rxe->tail : rxe->head;
    for (k = rev ? nsub - 1 : 0; a; a = rev ? a->prev : a->next, k += rev ? -1 : 1) {
        int branch = onpath && a == rxe->curr;
        char blabel[140];
        snprintf(blabel, sizeof blabel, "%s\n+%s", subs[k].start, subs[k].card);
        draw_seq(w, aid, k, a, branch, blabel);
    }
    free(subs); free(sbuf); free(cbuf); free(sxbuf); free(cxbuf);
}

void rxe_graph_walk(struct rxe *rxe, const struct rxe_graph_opts *opts,
                    const struct rxe_graph_visitor *v, void *ctx) {
    struct walk w = { 0 };
    w.v = v; w.ctx = ctx; w.opts = opts; w.root = rxe; w.source = rxe->source;
    w.idc = 0;
    int root = w.idc++;
    char card[64], cardx[64], text[128];
    text[0] = 0;
    int inf = rxe_is_infinite(rxe);
    gnum(card, sizeof card, rxe->nitems, inf);
    gexact(cardx, sizeof cardx, rxe->nitems, inf);
    if (opts->on_path) rxe_current(text, sizeof text, rxe);
    struct rxe_gnode_ev ev = { 0 };
    ev.id = root; ev.kind = RXE_G_ROOT; ev.line1 = "set"; ev.card = card;
    ev.card_exact = cardx; ev.is_inf = inf; ev.on_path = opts->on_path;
    ev.text = opts->on_path ? text : NULL; ev.ref_to = -1;
    v->node(ctx, &ev);
    draw_contents(&w, root, rxe, opts->on_path);
}
