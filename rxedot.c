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

// Draw a (?N) subroutine as a reference back to its group (compact), or in
// full (clearer when following a path, since each call goes its own way).
static int g_collapse = 1;

// Unroll a fixed {n} repetition into n copies of its body when n is at most
// this; 0 (the default) never unrolls. A repetition left rolled up still lists
// what each iteration chose, under -f, so nothing is lost -- just compact.
static int g_unroll = 0;

// Show the input regex as a title above the tree; on by default, off with -t.
static int g_title = 1;

// Fold a run of fixed single characters into one word node; on by default,
// off with -w so each character is drawn as its own leaf.
static int g_fold = 1;

// Text safe inside a Graphviz HTML-like label: the few markup characters
// become entities, and a control byte a numeric reference rather than a break.
static void html_escape(FILE *f, const char *s) {
    for (; *s; s++) {
        unsigned char c = *s;
        if      (c == '&') fputs("&amp;", f);
        else if (c == '<') fputs("&lt;", f);
        else if (c == '>') fputs("&gt;", f);
        else if (c == '"') fputs("&quot;", f);
        else if (c < 32 || c == 127) fprintf(f, "&#%d;", c);
        else fputc(c, f);
    }
}

// The pieces a fixed repetition's iterations produced under -f, space-joined
// and capped, read from the seeked tree by pointing the body at each stored
// index in turn.
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
static void node_source(char *b, size_t n, struct rxe_node *node) {
    int a = node->src_start, e = node->src_end;
    if (!g_source || e <= a || a < 0) { b[0] = 0; return; }
    size_t len = (size_t)(e - a);
    if (len >= n) len = n - 1;
    memcpy(b, g_source + a, len);
    b[len] = 0;
}

// The colour of the -f path: the route from the root to one member, lit along
// its edges and node borders so the reader can check the finger-slide.
#define HL "#d1442a"

static void draw_contents(FILE *f, int parent, struct rxe *rxe, int onpath);

// Draw one node of a concatenation and return its id. Leaves are labelled with
// their exact source text -- '[a-z]', '\d', '[:name:]', '\1', '(?2)' -- read
// from the span; structural nodes carry their kind and their children the rest.
static int draw_node(FILE *f, struct rxe_node *node, const char *weight,
                     int onpath) {
    int id = idc++;
    char kind[256], card[64], label[600], src[220];
    const char *fill = "#ffffff";
    int inf = node->is_inf, recurse = 0, refedge = -1, unroll = 0;
    char choices[200];
    choices[0] = 0;
    node_source(src, sizeof src, node);
    int have_src = src[0] != 0;

    if (node->refers_to) {                        // a (?N) subroutine call
        snprintf(kind, sizeof kind, "%s", have_src ? src : "(?…)");
        fill = "#ffe0b0";
        if (g_collapse) refedge = map_get(node->refers_to);  // link to its group
        else recurse = 1;                          // or draw the copied body in full
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
        fill = "#d4e4ff";
        // A fixed run short enough is unrolled into a copy of the body per
        // iteration; otherwise the body is drawn once, and -f still lists what
        // each iteration chose beside it.
        int fixed = !node->is_inf && node->rep_max != RXE_REP_UNBOUNDED
                    && node->rep_min == node->rep_max;
        if (fixed && node->rep_max >= 1 && node->rep_max <= g_unroll)
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
    // type, then size, then the place value where it carries, then -- for a
    // rolled-up repeat under -f -- what each iteration chose.
    size_t lp = snprintf(label, sizeof label, "%s\n%s", kind, card);
    if (weight)     lp += snprintf(label + lp, sizeof label - lp, "\n%s", weight);
    if (choices[0]) lp += snprintf(label + lp, sizeof label - lp, "\n%s", choices);
    fprintf(f, "  n%d [label=\"", id);
    dot_escape(f, label);
    // On the path, a red border wins over the blue-ringed infinite mark.
    fprintf(f, "\", fillcolor=\"%s\"%s];\n", fill,
            onpath ? ", color=\"" HL "\", penwidth=2.4" :
            inf    ? ", color=\"#2f60c0\", penwidth=2" : "");

    if (unroll) {
        // One copy of the body per iteration; under -f each is pointed at the
        // index that iteration took, so it lights its own values.
        for (int i = 0; i < unroll; i++) {
            if (onpath && i < node->rep_count) rxe_seek(node->rxe, node->rep_digit[i]);
            draw_contents(f, id, node->rxe, onpath);
        }
    } else if (recurse && node->rxe) {
        draw_contents(f, id, node->rxe, onpath);
    }
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
                            struct rxe_node *last, int onpath) {
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
    fprintf(f, "\", fillcolor=\"#ffffff\"%s];\n",
            onpath ? ", color=\"" HL "\", penwidth=2.4" : "");
    return id;
}

// A concatenation node's place value: the product of the sizes of its less
// significant siblings -- those after it, or before it under (?L). Left at 1
// (and so not shown) for the least significant, or for any endless
// concatenation, where the order is by length rather than place value.
static void concat_weight(struct rxe_alt *a, struct rxe_node *nd, mpz_t w) {
    mpz_set_ui(w, 1);
    int l2r = a->owner && (a->owner->flags & RXE_FLAG_LEFT_TO_RIGHT);
    for (struct rxe_node *m = a->head; m; m = m->next) if (m->is_inf) return;
    for (struct rxe_node *m = l2r ? nd->prev : nd->next; m;
         m = l2r ? m->prev : m->next)
        mpz_mul(w, w, m->nitems);
}

// Draw one alternative's concatenation, hanging from `from` (a node id, or a
// node:port when it comes off an alternation subsection), folding literal runs
// and tagging each carrying digit with its place value.
static void draw_seq(FILE *f, const char *from, struct rxe_alt *a, int onpath) {
    // Every node of a concatenation is present in a member, so the whole run is
    // on the path if its alternative is.
    const char *edge = onpath ? " [color=\"" HL "\", penwidth=2.2]" : "";
    mpz_t w;
    mpz_init(w);
    for (struct rxe_node *nd = a->head; nd; ) {
        int nid;
        if (g_fold && is_lit(nd) && is_lit(nd->next)) {
            struct rxe_node *last = nd;
            while (is_lit(last->next)) last = last->next;
            nid = draw_literal_run(f, nd, last, onpath);
            nd = last->next;
        } else {
            char wbuf[48];
            const char *wp = NULL;
            if (mpz_cmp_ui(nd->nitems, 1) > 0) {
                concat_weight(a, nd, w);
                if (mpz_cmp_ui(w, 1) > 0) {   // 1 is the fastest digit; no need
                    char ws[40];
                    numshort(ws, sizeof ws, w, 0);
                    snprintf(wbuf, sizeof wbuf, "×%s", ws);
                    wp = wbuf;
                }
            }
            nid = draw_node(f, nd, wp, onpath);
            nd = nd->next;
        }
        fprintf(f, "  %s -> n%d%s;\n", from, nid, edge);
    }
    mpz_clear(w);
}

// Hang the alternations of `rxe` under `parent`. One alternative is a plain
// concatenation drawn straight under it. Several become a single rounded record
// -- one subsection per alternative, each labelled with where it starts in the
// numbering and, after a '+', how many it holds. The alternatives lie end to
// end, so a subsection's start plus its size is exactly the next one's start:
// that is how you pick a branch when seeking to an index. Each subsection is a
// port the branch hangs from.
static void draw_contents(FILE *f, int parent, struct rxe *rxe, int onpath) {
    map_put(rxe, parent);
    if (rxe->nalts <= 1) {
        char from[24];
        snprintf(from, sizeof from, "n%d", parent);
        if (rxe->head) draw_seq(f, from, rxe->head, onpath);
        return;
    }
    int aid = idc++, k = 0;
    fprintf(f, "  n%d [shape=Mrecord, fillcolor=\"#fff0c0\"%s, label=\"", aid,
            onpath ? ", color=\"" HL "\", penwidth=2.4" : "");
    for (struct rxe_alt *a = rxe->head; a; a = a->next, k++) {
        char start[64], card[64];
        numshort(start, sizeof start, a->start, 0);
        numshort(card, sizeof card, a->nitems, a->ninf > 0);
        fprintf(f, "%s<p%d>%s\\n+%s", k ? "|" : "", k, start, card);
    }
    fprintf(f, "\"];\n  n%d -> n%d%s;\n", parent, aid,
            onpath ? " [color=\"" HL "\", penwidth=2.2]" : "");
    k = 0;
    for (struct rxe_alt *a = rxe->head; a; a = a->next, k++) {
        char from[32];
        // Only the branch the seek chose (rxe->curr) stays on the path.
        int branch = onpath && a == rxe->curr;
        snprintf(from, sizeof from, "n%d:p%d", aid, k);
        draw_seq(f, from, a, branch);
    }
}

int main(int argc, char **argv) {
    const char *pattern = NULL, *findex = NULL;
    int collapse = -1;                             // -1: decide from -f below
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-f") && i + 1 < argc) findex = argv[++i];
        else if (!strcmp(argv[i], "-c")) collapse = 1;   // force compact
        else if (!strcmp(argv[i], "-e")) collapse = 0;   // force expanded
        else if (!strcmp(argv[i], "-u") && i + 1 < argc) g_unroll = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-t")) g_title = 0;
        else if (!strcmp(argv[i], "-w")) g_fold = 0;
        else pattern = argv[i];
    }
    if (!pattern) {
        fprintf(stderr, "usage: %s [-f index] [-c|-e] [-u n] [-t] <regex>\n"
                        "  prints Graphviz DOT of the parse tree on stdout.\n"
                        "  -f lights the path taken to reach one member.\n"
                        "  -c/-e collapse a (?N) subroutine to a reference, or draw\n"
                        "        it in full; default is collapsed, but expanded with -f.\n"
                        "  -u  unroll a fixed {k} repetition into k bodies when k<=n\n"
                        "        (default 0, none); rolled-up ones list their choices under -f.\n"
                        "  -t  omit the title (the regex, shown by default).\n"
                        "  -w  draw each literal character as its own node, not\n"
                        "        folded into a word.\n"
                        "  e.g. %s '([2-9TJQKA][SHDC]){{5}}' | dot -Tpng -o hand.png\n",
                argv[0], argv[0]);
        return 1;
    }
    // A path is clearer with each subroutine drawn out, since its calls diverge;
    // a plain structure view is smaller with them collapsed.
    g_collapse = (collapse >= 0) ? collapse : (findex ? 0 : 1);
    struct rxe *rxe = rxe_parse(pattern, 0);
    if (rxe_error(rxe)) {
        fprintf(stderr, "%s: %s\n", argv[0], rxe_error_message(rxe));
        rxe_free(rxe);
        return 1;
    }

    // -f seeks to a member; afterwards the tree's curr pointers spell the path,
    // and rxe_current spells the member itself, which the caption shows.
    int onpath = 0;
    char member[1024];
    member[0] = 0;
    if (findex) {
        mpz_t idx;
        mpz_init(idx);
        if (mpz_set_str(idx, findex, 10) == 0 && mpz_sgn(idx) >= 0
                && rxe_seek(rxe, idx) == 0) {
            onpath = 1;
            rxe_current(member, sizeof member - 1, rxe);
        } else {
            fprintf(stderr, "%s: no member at index %s\n", argv[0], findex);
        }
        mpz_clear(idx);
    }

    g_source = rxe->source;

    FILE *f = stdout;
    fprintf(f, "digraph rxe {\n");
    fprintf(f, "  graph [rankdir=TB, ordering=out, bgcolor=\"#ffffff\", "
               "fontname=\"Helvetica\"];\n");
    fprintf(f, "  node [shape=box, style=\"filled,rounded\", fontname=\"Helvetica\", "
               "fontsize=11, margin=\"0.10,0.05\"];\n");
    fprintf(f, "  edge [arrowsize=0.7, color=\"#888888\"];\n");
    // A title above the tree: the regex in monospace, and -- under -f -- the
    // index and the member it reaches, in the path's colour.
    if (g_title || onpath) {
        fprintf(f, "  labelloc=\"t\"; label=<");
        if (g_title) {
            fprintf(f, "<FONT FACE=\"Courier\" POINT-SIZE=\"15\">");
            html_escape(f, pattern);
            fprintf(f, "</FONT>");
        }
        if (onpath) {
            if (g_title) fprintf(f, "<BR/>");
            fprintf(f, "<FONT COLOR=\"" HL "\" POINT-SIZE=\"13\">index ");
            html_escape(f, findex);
            fprintf(f, " = ");
            html_escape(f, member);
            fprintf(f, "</FONT>");
        }
        fprintf(f, ">;\n");
    }

    int root = idc++;
    int inf = rxe_is_infinite(rxe);
    char card[64], label[160];
    numshort(card, sizeof card, rxe->nitems, inf);
    snprintf(label, sizeof label, "set\n%s", card);
    fprintf(f, "  n%d [shape=box, fillcolor=\"#333a44\", fontcolor=\"white\", "
               "style=\"filled,rounded\"%s, label=\"", root,
            onpath ? ", color=\"" HL "\", penwidth=2.4" : "");
    dot_escape(f, label);
    fprintf(f, "\"];\n");
    draw_contents(f, root, rxe, onpath);

    fprintf(f, "}\n");
    rxe_free(rxe);
    return 0;
}
