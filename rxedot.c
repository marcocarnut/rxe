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

// The option set of a one-position character class, previewed: a lone
// character bare, a small set in full, a large one as first..last.
static void class_preview(char *b, size_t n, struct rxe_node *node) {
    size_t p = 0;
    #define PUTC(ch) do { unsigned char _c = (unsigned char)(ch); \
        p += (_c >= 32 && _c < 127) ? snprintf(b + p, p < n ? n - p : 0, "%c", _c) \
                                    : snprintf(b + p, p < n ? n - p : 0, "<%02x>", _c); \
        } while (0)
    if (node->len <= 0) { snprintf(b, n, "ε"); return; }   // epsilon: empty
    if (node->len == 1) { PUTC(node->str[0]); return; }
    p += snprintf(b + p, p < n ? n - p : 0, "[");
    if (node->len <= 8) for (int i = 0; i < node->len; i++) PUTC(node->str[i]);
    else { PUTC(node->str[0]); p += snprintf(b + p, p < n ? n - p : 0, "…");
           PUTC(node->str[node->len - 1]); }
    p += snprintf(b + p, p < n ? n - p : 0, "]");
    #undef PUTC
}

static void draw_contents(FILE *f, int parent, struct rxe *rxe);

// Draw one node of a concatenation and return its id.
static int draw_node(FILE *f, struct rxe_node *node) {
    int id = idc++;
    char kind[128], card[64], label[220];
    const char *fill = "#ffffff";
    int inf = node->is_inf;

    if (node->is_backref) { snprintf(kind, sizeof kind, "\\ backref"); fill = "#ffe0b0"; }
    else if (node->is_repeat) {
        if (node->rep_max == RXE_REP_UNBOUNDED)
            snprintf(kind, sizeof kind, "repeat {%d,}", node->rep_min);
        else if (node->rep_min == node->rep_max)
            snprintf(kind, sizeof kind, "repeat {%d}", node->rep_min);
        else snprintf(kind, sizeof kind, "repeat {%d,%d}", node->rep_min, node->rep_max);
        fill = "#d4e4ff";
    }
    else if (node->is_comb) {
        const char *verb = node->comb_perm ? "permute" : "choose";
        const char *bang = node->comb_perm ? "!" : "";
        if (node->rep_min == node->rep_max)
            snprintf(kind, sizeof kind, "%s {{%d%s}}", verb, node->rep_min, bang);
        else snprintf(kind, sizeof kind, "%s {{%d,%d%s}}", verb,
                      node->rep_min, node->rep_max, bang);
        fill = "#ffd4e6";
    }
    else if (node->is_shuffle) { snprintf(kind, sizeof kind, "shuffle (?~…)"); fill = "#e6d4ff"; }
    else if (node->is_dict)    { snprintf(kind, sizeof kind, "dict · %d words", node->nwords); fill = "#d4f4d4"; }
    else if (node->rxe)        { snprintf(kind, sizeof kind, "group ( )"); fill = "#eeeeee"; }
    else { char cp[80]; class_preview(cp, sizeof cp, node);
           snprintf(kind, sizeof kind, "%s", cp); fill = "#ffffff"; }

    numshort(card, sizeof card, node->nitems, inf);
    snprintf(label, sizeof label, "%s\n%s", kind, card);
    fprintf(f, "  n%d [label=\"", id);
    dot_escape(f, label);
    fprintf(f, "\", fillcolor=\"%s\"%s];\n", fill,
            inf ? ", color=\"#2f60c0\", penwidth=2" : "");

    if (node->is_backref) {
        int g = node->rxe ? map_get(node->rxe) : -1;
        if (g >= 0)
            fprintf(f, "  n%d -> n%d [style=dashed, constraint=false, "
                       "color=\"#c07000\", arrowsize=0.6];\n", id, g);
    } else if (node->rxe) {
        draw_contents(f, id, node->rxe);
    }
    return id;
}

// Hang the alternations of `rxe` under the box `parent`. A single alternation
// is just a concatenation, drawn straight under it; several become a fan of
// diamonds, each showing where in the numbering it starts.
static void draw_contents(FILE *f, int parent, struct rxe *rxe) {
    map_put(rxe, parent);
    int single = (rxe->nalts <= 1);
    for (struct rxe_alt *a = rxe->head; a; a = a->next) {
        int p = parent;
        if (!single) {
            int aid = idc++;
            char card[64], start[64], label[160];
            numshort(card, sizeof card, a->nitems, a->ninf > 0);
            numshort(start, sizeof start, a->start, 0);
            snprintf(label, sizeof label, "|\nstart %s\n%s", start, card);
            fprintf(f, "  n%d [shape=diamond, fillcolor=\"#fff0c0\", label=\"", aid);
            dot_escape(f, label);
            fprintf(f, "\"];\n  n%d -> n%d;\n", parent, aid);
            p = aid;
        }
        for (struct rxe_node *nd = a->head; nd; nd = nd->next) {
            int nid = draw_node(f, nd);
            fprintf(f, "  n%d -> n%d;\n", p, nid);
        }
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
