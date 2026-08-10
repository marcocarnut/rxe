/*
 * rxedot - draw a regex's parse tree as Graphviz DOT
 *
 * A sibling to rxenum, not part of the library: it parses an expression with
 * librxe, then walks the finished tree and prints a graph. The library knows
 * nothing of DOT; this reads the same public structs rxenum does and turns
 * them into a picture. Pipe it into Graphviz:
 *
 *     rxedot '([2-9TJQKA][SHDC]){{5}}' | dot -Tpng -o hand.png
 *
 * Each node carries its cardinality, so the arithmetic of the set is visible:
 * a concatenation multiplies its children, an alternation sums them, a {{k}}
 * is C(n,k) or P(n,k). An infinite node is drawn ringed; a backreference is a
 * dashed edge back to the group it repeats.
 *
 * This program is free software under the GNU General Public License v2 or
 * later; see http://www.gnu.org/licenses/gpl-2.0.html.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmp.h>
#include "rxe.h"

static int idc;                       // next node id; sequential, so output is
                                      // deterministic across runs

// Every group's rxe is remembered against the id of the box that stands for
// it, so a backreference can draw a dashed edge to the real thing.
static struct { struct rxe *rxe; int id; } gmap[8192];
static int gmapn;
static void map_put(struct rxe *r, int id) {
    if (gmapn < (int)(sizeof gmap / sizeof *gmap)) {
        gmap[gmapn].rxe = r; gmap[gmapn].id = id; gmapn++;
    }
}
static int map_get(struct rxe *r) {
    for (int i = 0; i < gmapn; i++) if (gmap[i].rxe == r) return gmap[i].id;
    return -1;
}

// A DOT label between quotes: a real newline becomes a line break, the few
// characters DOT reads specially are escaped, and a control byte is shown as
// <hex> so it cannot break the file.
static void dot_escape(FILE *f, const char *s) {
    for (; *s; s++) {
        unsigned char c = *s;
        if      (c == '"')  fputs("\\\"", f);
        else if (c == '\\') fputs("\\\\", f);
        else if (c == '\n') fputs("\\n", f);
        else if (c < 32 || c == 127) fprintf(f, "<%02x>", c);
        else fputc(c, f);
    }
}

// A cardinality, short enough to fit in a box: the exact number up to fifteen
// digits, an order-of-magnitude sketch beyond, and the infinity sign when the
// set has no largest member.
static void numshort(char *b, size_t n, const mpz_t v, int inf) {
    if (inf) { snprintf(b, n, "∞"); return; }
    char *s = mpz_get_str(NULL, 10, v);
    size_t len = strlen(s);
    if (len <= 15) snprintf(b, n, "%s", s);
    else snprintf(b, n, "~%c.%c%c%ce%zu", s[0], s[1], s[2], s[3], len - 1);
    free(s);
}

// The root's source text, so a node's exact input can be read from its span.
static const char *g_source;
static void node_source(char *b, size_t n, struct rxe_node *node) {
    int a = node->src_start, e = node->src_end;
    if (!g_source || e <= a || a < 0) { b[0] = 0; return; }
    size_t len = (size_t)(e - a);
    if (len >= n) len = n - 1;
    memcpy(b, g_source + a, len);
    b[len] = 0;
}

static void draw_contents(FILE *f, int parent, struct rxe *rxe);

// Draw one node of a concatenation and return its id. Leaves are labelled with
// their exact source text -- '[a-z]', '\d', '[:name:]', '\1', '(?2)' -- read
// from the span; structural nodes carry their kind and their children the rest.
static int draw_node(FILE *f, struct rxe_node *node) {
    int id = idc++;
    char kind[256], card[64], label[340], src[220];
    const char *fill = "#ffffff";
    int inf = node->is_inf, recurse = 0, refedge = -1;
    node_source(src, sizeof src, node);
    int have_src = src[0] != 0;

    if (node->refers_to) {                        // a (?N) subroutine call
        snprintf(kind, sizeof kind, "%s", have_src ? src : "(?…)");
        fill = "#ffe0b0";
        refedge = map_get(node->refers_to);       // a link to the group it copies
    }
    else if (node->is_backref) {                  // a \N backreference
        snprintf(kind, sizeof kind, "%s", have_src ? src : "\\ref");
        fill = "#ffe0b0";
        refedge = node->rxe ? map_get(node->rxe) : -1;
    }
    else if (node->is_repeat) {
        if (node->rep_max == RXE_REP_UNBOUNDED)
            snprintf(kind, sizeof kind, "repeat {%d,}", node->rep_min);
        else if (node->rep_min == node->rep_max)
            snprintf(kind, sizeof kind, "repeat {%d}", node->rep_min);
        else snprintf(kind, sizeof kind, "repeat {%d,%d}", node->rep_min, node->rep_max);
        fill = "#d4e4ff"; recurse = 1;
    }
    else if (node->is_comb) {
        const char *verb = node->comb_perm ? "permute" : "choose";
        const char *bang = node->comb_perm ? "!" : "";
        if (node->rep_min == node->rep_max)
            snprintf(kind, sizeof kind, "%s {{%d%s}}", verb, node->rep_min, bang);
        else snprintf(kind, sizeof kind, "%s {{%d,%d%s}}", verb,
                      node->rep_min, node->rep_max, bang);
        fill = "#ffd4e6"; recurse = 1;
    }
    else if (node->is_shuffle) { snprintf(kind, sizeof kind, "shuffle (?~…)"); fill = "#e6d4ff"; recurse = 1; }
    else if (node->is_dict)    { snprintf(kind, sizeof kind, "%s", have_src ? src : "dict"); fill = "#d4f4d4"; }
    else if (node->rxe)        { snprintf(kind, sizeof kind, "( )"); fill = "#eeeeee"; recurse = 1; }
    else { snprintf(kind, sizeof kind, "%s", have_src ? src : "?"); fill = "#ffffff"; }

    numshort(card, sizeof card, node->nitems, inf);
    snprintf(label, sizeof label, "%s\n%s", kind, card);
    fprintf(f, "  n%d [label=\"", id);
    dot_escape(f, label);
    fprintf(f, "\", fillcolor=\"%s\"%s];\n", fill,
            inf ? ", color=\"#2f60c0\", penwidth=2" : "");

    if (recurse && node->rxe) draw_contents(f, id, node->rxe);
    if (refedge >= 0)
        fprintf(f, "  n%d -> n%d [style=dashed, constraint=false, "
                   "color=\"#c07000\", arrowsize=0.6];\n", id, refedge);
    return id;
}

// A fixed single character: a plain leaf of exactly one member, with a span to
// read it from. A run of these is a literal word, and reads better whole.
static int is_lit(struct rxe_node *n) {
    return n && !n->rxe && !n->is_backref && !n->is_repeat && !n->is_comb
        && !n->is_shuffle && !n->is_dict && !n->refers_to
        && n->src_end > n->src_start && mpz_cmp_ui(n->nitems, 1) == 0;
}

// One node for a run of literals from 'first' to 'last', labelled with the
// stretch of source they span -- 'cat' rather than three boxes 'c' 'a' 't'.
static int draw_literal_run(FILE *f, struct rxe_node *first,
                            struct rxe_node *last) {
    int id = idc++;
    char src[256], label[300];
    int a = first->src_start, e = last->src_end, len = e - a;
    if (len < 0) len = 0;
    if ((size_t)len >= sizeof src) len = sizeof src - 1;
    memcpy(src, g_source + a, len);
    src[len] = 0;
    snprintf(label, sizeof label, "%s\n1", src);
    fprintf(f, "  n%d [label=\"", id);
    dot_escape(f, label);
    fprintf(f, "\", fillcolor=\"#ffffff\"];\n");
    return id;
}

// Draw one alternative's concatenation, hanging from `from` (a node id, or a
// node:port when it comes off an alternation subsection), folding literal runs.
static void draw_seq(FILE *f, const char *from, struct rxe_alt *a) {
    for (struct rxe_node *nd = a->head; nd; ) {
        int nid;
        if (is_lit(nd) && is_lit(nd->next)) {
            struct rxe_node *last = nd;
            while (is_lit(last->next)) last = last->next;
            nid = draw_literal_run(f, nd, last);
            nd = last->next;
        } else {
            nid = draw_node(f, nd);
            nd = nd->next;
        }
        fprintf(f, "  %s -> n%d;\n", from, nid);
    }
}

// Hang the alternations of `rxe` under `parent`. One alternative is a plain
// concatenation drawn straight under it. Several become a single rounded record
// -- one subsection per alternative, each labelled with where it starts in the
// numbering and, after a '+', how many it holds. The alternatives lie end to
// end, so a subsection's start plus its size is exactly the next one's start:
// that is how you pick a branch when seeking to an index. Each subsection is a
// port the branch hangs from.
static void draw_contents(FILE *f, int parent, struct rxe *rxe) {
    map_put(rxe, parent);
    if (rxe->nalts <= 1) {
        char from[24];
        snprintf(from, sizeof from, "n%d", parent);
        if (rxe->head) draw_seq(f, from, rxe->head);
        return;
    }
    int aid = idc++, k = 0;
    fprintf(f, "  n%d [shape=Mrecord, fillcolor=\"#fff0c0\", label=\"", aid);
    for (struct rxe_alt *a = rxe->head; a; a = a->next, k++) {
        char start[64], card[64];
        numshort(start, sizeof start, a->start, 0);
        numshort(card, sizeof card, a->nitems, a->ninf > 0);
        fprintf(f, "%s<p%d>%s\\n+%s", k ? "|" : "", k, start, card);
    }
    fprintf(f, "\"];\n  n%d -> n%d;\n", parent, aid);
    k = 0;
    for (struct rxe_alt *a = rxe->head; a; a = a->next, k++) {
        char from[32];
        snprintf(from, sizeof from, "n%d:p%d", aid, k);
        draw_seq(f, from, a);
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <regex>\n"
                        "  prints Graphviz DOT of the parse tree on stdout.\n"
                        "  e.g. %s '([2-9TJQKA][SHDC]){{5}}' | dot -Tpng -o hand.png\n",
                argv[0], argv[0]);
        return 1;
    }
    struct rxe *rxe = rxe_parse(argv[1], 0);
    if (rxe_error(rxe)) {
        fprintf(stderr, "%s: %s\n", argv[0], rxe_error_message(rxe));
        rxe_free(rxe);
        return 1;
    }

    g_source = rxe->source;

    FILE *f = stdout;
    fprintf(f, "digraph rxe {\n");
    fprintf(f, "  graph [rankdir=TB, ordering=out, bgcolor=\"#ffffff\", "
               "fontname=\"Helvetica\"];\n");
    fprintf(f, "  node [shape=box, style=\"filled,rounded\", fontname=\"Helvetica\", "
               "fontsize=11, margin=\"0.10,0.05\"];\n");
    fprintf(f, "  edge [arrowsize=0.7, color=\"#888888\"];\n");

    int root = idc++;
    int inf = rxe_is_infinite(rxe);
    char card[64], label[160];
    numshort(card, sizeof card, rxe->nitems, inf);
    snprintf(label, sizeof label, "set\n%s", card);
    fprintf(f, "  n%d [shape=box, fillcolor=\"#333a44\", fontcolor=\"white\", "
               "style=\"filled,rounded\", label=\"", root);
    dot_escape(f, label);
    fprintf(f, "\"];\n");
    draw_contents(f, root, rxe);

    fprintf(f, "}\n");
    rxe_free(rxe);
    return 0;
}
