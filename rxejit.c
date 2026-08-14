/*
 * rxejit - compile a regex-set into C that enumerates it.
 *
 *          rxenum walks the set through the library's interpreter: a tree of
 *          nodes, an mpz index, a function call per member. For a bruteforce --
 *          keycracking, dedup, fuzzing -- that interpreter is the whole cost,
 *          and the benchmark said so. This emits C specialised to one regex
 *          instead: an unrolled odometer over fixed char buffers, incremented
 *          by carry, that the system compiler then optimises. No tree, no mpz,
 *          no indirect call.
 *
 *          This first cut handles the fixed-width mask -- a run of single-
 *          character classes and their exact repeats, [a-z]{4}[0-9]{2} and the
 *          like, the classic shape of a mask attack. Anything else (an
 *          alternation, a dictionary, an unbounded or variable repeat, a
 *          backreference) it declines, naming what it could not take, so the
 *          interpreter path stays the answer for those. The C it prints is a
 *          standalone program that writes every member to stdout, in exactly
 *          rxenum -e's order; a later cut compiles and runs it, and swaps the
 *          write for a chosen sink.
 *
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rxe.h"

#define MAXW 4096                  // most positions an unrolled mask may have

// One odometer wheel: the ordered bytes a single position steps through, drawn
// straight from a class node's string so the order is the enumeration's.
struct wheel { const char *a; int n; };

static const char *reason;         // why a pattern was declined, for the message

// A plain single-character class -- none of the compound flags, no
// subexpression -- yields one wheel. Returns 0 and fills a/n, or -1.
static int class_of(struct rxe_node *nd, const char **a, int *n)
{
    if (nd->is_repeat || nd->is_comb || nd->is_shuffle ||
        nd->is_dict || nd->is_backref || nd->is_inf || nd->rxe)
        return -1;
    *a = nd->str;
    *n = nd->len;
    return 0;
}

// Flatten a mask into its wheels, left to right. Returns the count, or -1 with
// 'reason' set for the first thing that is not a fixed run of classes.
static int collect(struct rxe *rxe, struct wheel *w)
{
    if (rxe->flags & (RXE_FLAG_LEFT_TO_RIGHT | RXE_FLAG_SHORTLEX)) {
        reason = "a non-default enumeration order"; return -1;
    }
    if (!rxe->head || rxe->head->next) {       // more than one alternation
        reason = "a top-level alternation"; return -1;
    }
    int nw = 0;
    for (struct rxe_node *nd = rxe->head->head; nd; nd = nd->next) {
        const char *a; int n, reps = 1;
        if (class_of(nd, &a, &n) != 0) {
            // The one compound we take: an exact {k} repeat of a plain class.
            struct rxe *b = nd->rxe;
            if (nd->is_repeat && !nd->is_inf && nd->rep_max != RXE_REP_UNBOUNDED &&
                nd->rep_min == nd->rep_max &&
                b && b->head && !b->head->next && b->head->head &&
                !b->head->head->next && class_of(b->head->head, &a, &n) == 0) {
                reps = nd->rep_min;
            } else {
                reason = nd->is_inf     ? "an unbounded repeat"
                       : nd->is_dict    ? "a dictionary"
                       : nd->is_backref ? "a backreference"
                       : nd->is_comb    ? "a combination"
                       : nd->is_shuffle ? "a shuffle"
                       : nd->is_repeat  ? "a variable-count repeat"
                       : nd->rxe        ? "a group"
                       :                  "an unsupported element";
                return -1;
            }
        }
        if (n < 1) { reason = "an empty class"; return -1; }
        for (int k = 0; k < reps; k++) {
            if (nw >= MAXW) { reason = "too many positions to unroll"; return -1; }
            w[nw].a = a; w[nw].n = n; nw++;
        }
    }
    return nw;
}

// Print the pattern into a C comment, defusing any */ that would close it.
static void emit_comment(FILE *o, const char *s)
{
    for (; *s; s++) fputc((*s == '*' && s[1] == '/') ? ' ' : *s, o);
}

// The generated program. Each wheel is a byte at buf[w]; the member is those
// bytes plus a trailing newline, so a whole line is one fwrite. The odometer
// steps from the least significant wheel (the last, as the interpreter counts),
// rewriting only the byte that turned -- the delta render the tree walk cannot
// do -- and stops when the most significant wheel carries out.
static void emit(FILE *o, const char *pattern, struct wheel *w, int nw)
{
    fputs("/* generated by rxejit from: ", o);
    emit_comment(o, pattern);
    fputs(" */\n#include <stdio.h>\n\nint main(void)\n{\n", o);

    for (int i = 0; i < nw; i++) {
        fprintf(o, "    static const unsigned char A%d[] = {", i);
        for (int j = 0; j < w[i].n; j++)
            fprintf(o, "%s%d", j ? "," : "", (unsigned char)w[i].a[j]);
        fputs("};\n", o);
    }

    fprintf(o, "    unsigned char buf[%d];\n", nw + 1);
    fprintf(o, "    buf[%d] = '\\n';\n", nw);
    for (int i = 0; i < nw; i++)
        fprintf(o, "    int i%d = 0; buf[%d] = A%d[0];\n", i, i, i);

    fputs("    for (;;) {\n", o);
    fprintf(o, "        fwrite(buf, 1, %d, stdout);\n", nw + 1);
    for (int i = nw - 1; i >= 0; i--)
        fprintf(o, "        if (++i%d < %d) { buf[%d] = A%d[i%d]; continue; }"
                   " i%d = 0; buf[%d] = A%d[0];\n",
                i, w[i].n, i, i, i, i, i, i);
    fputs("        break;\n    }\n    return 0;\n}\n", o);
}

int main(int argc, char **argv)
{
    const char *prog = argc > 0 ? argv[0] : "rxejit";
    if (argc != 2) {
        fprintf(stderr, "usage: %s REGEX\n"
            "  Print C that enumerates the set REGEX describes, to stdout.\n"
            "  Handles a fixed-width mask of single-character classes; other\n"
            "  patterns are declined with a reason.\n", prog);
        return 2;
    }

    rxe_init();
    struct rxe *rxe = rxe_parse(argv[1], 0);
    if (rxe_error(rxe) != RXE_OK) {
        fprintf(stderr, "%s: %s\n", prog, rxe_error_message(rxe));
        rxe_free(rxe);
        return 2;
    }

    struct wheel *w = malloc(MAXW * sizeof *w);
    if (!w) { fprintf(stderr, "%s: out of memory\n", prog); rxe_free(rxe); return 2; }

    int nw = collect(rxe, w);
    if (nw < 0) {
        fprintf(stderr, "%s: cannot compile this pattern yet -- it has %s.\n",
                prog, reason);
        free(w); rxe_free(rxe); return 1;
    }

    emit(stdout, argv[1], w, nw);
    free(w);
    rxe_free(rxe);
    return 0;
}
