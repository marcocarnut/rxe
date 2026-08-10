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
 * The tree-walk itself lives in the library now (rxe_graph_walk): this file is
 * only the DOT backend, three callbacks that turn each node and edge the walk
 * hands over into a line of DOT. The browser draws the same walk as JSON.
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
#include "rxe_graph.h"

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

// The colour of the -f path: the route from the root to one member, lit along
// its edges and node borders so the reader can check the finger-slide.
#define HL "#d1442a"

// The fill each kind of node is drawn with; the walk hands over the kind, the
// backend picks the colour, exactly the palette rxedot always used.
static const char *fill_for(enum rxe_gkind k) {
    switch (k) {
        case RXE_G_SUBROUTINE:
        case RXE_G_BACKREF:  return "#ffe0b0";
        case RXE_G_REPEAT:   return "#d4e4ff";
        case RXE_G_COMB:     return "#ffd4e6";
        case RXE_G_SHUFFLE:  return "#e6d4ff";
        case RXE_G_DICT:     return "#d4f4d4";
        case RXE_G_GROUP:    return "#eeeeee";
        default:             return "#ffffff";   // LEAF, LITERAL
    }
}

// One node. The root is the dark set box; every other node joins its label
// pieces (kind, size, place value, chosen pieces) top to bottom, fills by kind,
// and takes a red border on the path or a blue ring when infinite.
static void dot_node(void *cx, const struct rxe_gnode_ev *n) {
    FILE *f = cx;
    char label[900];
    size_t lp = snprintf(label, sizeof label, "%s\n%s", n->line1, n->card);
    if (n->place)   lp += snprintf(label + lp, sizeof label - lp, "\n%s", n->place);
    if (n->choices) lp += snprintf(label + lp, sizeof label - lp, "\n%s", n->choices);

    if (n->kind == RXE_G_ROOT) {
        fprintf(f, "  n%d [shape=box, fillcolor=\"#333a44\", fontcolor=\"white\", "
                   "style=\"filled,rounded\"%s, label=\"", n->id,
                n->on_path ? ", color=\"" HL "\", penwidth=2.4" : "");
        dot_escape(f, label);
        fprintf(f, "\"];\n");
        return;
    }
    fprintf(f, "  n%d [label=\"", n->id);
    dot_escape(f, label);
    // On the path, a red border wins over the blue-ringed infinite mark.
    fprintf(f, "\", fillcolor=\"%s\"%s];\n", fill_for(n->kind),
            n->on_path ? ", color=\"" HL "\", penwidth=2.4" :
            n->is_inf  ? ", color=\"#2f60c0\", penwidth=2" : "");
}

// An alternation, drawn as a rounded record: one subsection per branch, each
// labelled with where it starts in the numbering and, after a '+', how many it
// holds. The alternatives lie end to end, so a subsection's start plus its size
// is exactly the next one's start: that is how you pick a branch when seeking.
static void dot_alt(void *cx, const struct rxe_galt_ev *a) {
    FILE *f = cx;
    fprintf(f, "  n%d [shape=Mrecord, fillcolor=\"#fff0c0\"%s, label=\"", a->id,
            a->on_path ? ", color=\"" HL "\", penwidth=2.4" : "");
    for (int k = 0; k < a->nsub; k++)
        fprintf(f, "%s<p%d>%s\\n+%s", k ? "|" : "", k, a->subs[k].start, a->subs[k].card);
    fprintf(f, "\"];\n");
}

// One edge. A subroutine or backref is a dashed back-edge that does not pull on
// the layout; every other edge is a plain arrow, red when on the path, and
// leaves an alternation subsection's port when it has one.
static void dot_edge(void *cx, const struct rxe_gedge_ev *e) {
    FILE *f = cx;
    if (e->is_ref) {
        fprintf(f, "  n%d -> n%d [style=dashed, constraint=false, "
                   "color=\"#c07000\", arrowsize=0.6];\n", e->from, e->to);
        return;
    }
    const char *hl = e->on_path ? " [color=\"" HL "\", penwidth=2.2]" : "";
    if (e->from_port >= 0)
        fprintf(f, "  n%d:p%d -> n%d%s;\n", e->from, e->from_port, e->to, hl);
    else
        fprintf(f, "  n%d -> n%d%s;\n", e->from, e->to, hl);
}

int main(int argc, char **argv) {
    const char *pattern = NULL, *findex = NULL;
    int collapse = -1;                             // -1: decide from -f below
    int unroll = 0, title = 1, fold = 1;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-f") && i + 1 < argc) findex = argv[++i];
        else if (!strcmp(argv[i], "-c")) collapse = 1;   // force compact
        else if (!strcmp(argv[i], "-e")) collapse = 0;   // force expanded
        else if (!strcmp(argv[i], "-u") && i + 1 < argc) unroll = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-t")) title = 0;
        else if (!strcmp(argv[i], "-w")) fold = 0;
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
    int do_collapse = (collapse >= 0) ? collapse : (findex ? 0 : 1);
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

    FILE *f = stdout;
    fprintf(f, "digraph rxe {\n");
    fprintf(f, "  graph [rankdir=TB, ordering=out, bgcolor=\"#ffffff\", "
               "fontname=\"Helvetica\"];\n");
    fprintf(f, "  node [shape=box, style=\"filled,rounded\", fontname=\"Helvetica\", "
               "fontsize=11, margin=\"0.10,0.05\"];\n");
    fprintf(f, "  edge [arrowsize=0.7, color=\"#888888\"];\n");
    // A title above the tree: the regex in monospace, and -- under -f -- the
    // index and the member it reaches, in the path's colour.
    if (title || onpath) {
        fprintf(f, "  labelloc=\"t\"; label=<");
        if (title) {
            fprintf(f, "<FONT FACE=\"Courier\" POINT-SIZE=\"15\">");
            html_escape(f, pattern);
            fprintf(f, "</FONT>");
        }
        if (onpath) {
            if (title) fprintf(f, "<BR/>");
            fprintf(f, "<FONT COLOR=\"" HL "\" POINT-SIZE=\"13\">index ");
            html_escape(f, findex);
            fprintf(f, " = ");
            html_escape(f, member);
            fprintf(f, "</FONT>");
        }
        fprintf(f, ">;\n");
    }

    // letters and alt_reverse stay off: they shape the browser's drawing, not
    // the DOT, and turning either on would move this output.
    struct rxe_graph_opts opts = { .collapse = do_collapse, .unroll = unroll,
                                   .fold = fold, .on_path = onpath };
    struct rxe_graph_visitor vis = { dot_node, dot_alt, dot_edge };
    rxe_graph_walk(rxe, &opts, &vis, f);

    fprintf(f, "}\n");
    rxe_free(rxe);
    return 0;
}
