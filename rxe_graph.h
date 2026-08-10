/*
 * rxe_graph - one traversal of a parsed regex's tree, for every client that
 *             wants to draw it.
 *
 * rxedot drew the parse tree by walking the public structs and printing DOT
 * inline. The browser wants the same tree as JSON. Rather than let the two
 * walks drift, the walk itself lives here, in the library, and a client only
 * supplies what to *emit*: three callbacks, driven in a fixed order over the
 * nodes and edges of the tree. rxedot's callbacks print DOT; the wasm binding's
 * build JSON. The library still knows nothing of either format -- it hands out
 * a node's kind, its label pieces, its cardinality, and the edges between
 * nodes, already computed, and the client turns them into a picture.
 *
 * The order of the callbacks is deliberately the order rxedot used to print in,
 * so its output is unchanged to the byte (see tests/rxedot.sh). A node id is
 * assigned in traversal order, the same sequence rxedot's counter used.
 *
 * This program is free software under the GNU General Public License v2 or
 * later; see http://www.gnu.org/licenses/gpl-2.0.html.
 */

#ifndef __RXE_GRAPH_H__
#define __RXE_GRAPH_H__

#include "rxe.h"

// What a node stands for. The kind is all a renderer needs to colour it; the
// label text is handed over separately. LEAF covers a plain character class or
// single literal; LITERAL is a folded run of fixed characters ('cat').
enum rxe_gkind {
    RXE_G_ROOT,        // the whole set, drawn as the dark root box
    RXE_G_LEAF,        // a character class or single literal
    RXE_G_LITERAL,     // a folded run of fixed characters, e.g. 'cat'
    RXE_G_GROUP,       // a plain parenthesised subexpression
    RXE_G_ALT,         // an alternation: several branches (the record node)
    RXE_G_REPEAT,      // a repetition, {n}, *, +, {n,m}
    RXE_G_COMB,        // a combinatorial choose/permute, {{k}} / {{k!}}
    RXE_G_SHUFFLE,     // a keyed shuffle, (?~key:)
    RXE_G_DICT,        // a named dictionary, [:name:]
    RXE_G_SUBROUTINE,  // a (?N) subroutine call
    RXE_G_BACKREF      // a \N backreference
};

// A node emitted to the visitor. The label pieces are pre-formatted strings the
// renderer joins as it likes: 'line1' the top line (the source span or a
// synthesized kind such as "repeat {2}"), 'card' the cardinality (a decimal, or
// the infinity sign), 'place' the "x N" place value or NULL, 'choices' the
// per-iteration list under a lit path or NULL. The pointers are valid only for
// the duration of the callback; copy what you keep.
struct rxe_gnode_ev {
    int              id;
    enum rxe_gkind   kind;
    const char      *line1;
    const char      *card;
    int              is_inf;    // the set at this node has no largest member
    const char      *place;     // place value "x N", or NULL
    const char      *choices;   // rolled-up repeat's chosen pieces, or NULL
    int              on_path;    // lit by a -f/rank path
    int              ref_to;     // referenced node id (subroutine/backref), or -1
    int              rep_min, rep_max;  // for REPEAT/COMB; else 0
    int              comb_perm;         // for COMB: ordered (permute) vs not
};

// One subsection of an alternation: where its branch begins in the numbering
// and how many members it holds. start + card of one is the start of the next.
struct rxe_gsub { const char *start; const char *card; int is_inf; };

// An alternation node, emitted before its branches. The subsections describe
// the record's cells; the branch edges follow as ordinary edge events whose
// from_port selects the cell.
struct rxe_galt_ev {
    int                     id;
    int                     on_path;
    int                     nsub;
    const struct rxe_gsub  *subs;
};

// An edge from one node to another. from_port is the alternation subsection the
// edge leaves, or -1 for a plain edge. is_ref marks the dashed back-edge of a
// subroutine or backreference. label carries an alternation branch's
// "start / +size" for renderers that put it on the edge; DOT ignores it (the
// text lives in the record cell instead), so it is NULL for non-branch edges.
struct rxe_gedge_ev {
    int          from;
    int          from_port;
    int          to;
    int          on_path;
    int          is_ref;
    const char  *label;
};

// The three emit points, driven in a fixed order by the walk.
struct rxe_graph_visitor {
    void (*node)(void *ctx, const struct rxe_gnode_ev *n);
    void (*alt) (void *ctx, const struct rxe_galt_ev  *a);
    void (*edge)(void *ctx, const struct rxe_gedge_ev *e);
};

// How to walk. collapse draws a (?N) as a link back to its group rather than a
// full copy; unroll expands a fixed {k} into k bodies when k <= unroll; fold
// runs a stretch of fixed characters into one literal word; on_path marks the
// whole walk as lighting a path (the tree's curr pointers, set by a prior seek,
// pick which branches stay lit). letters, on top of fold, also hands over each
// folded word's own characters as child leaves, so a drawing can unfold 'cat'
// into 'c' 'a' 't' -- each letter carrying its own source, which is why the
// library does the splitting rather than the client (an escape like '\.' is one
// letter, not two). Nothing emits them unless asked; rxedot leaves this off.
struct rxe_graph_opts { int collapse, unroll, fold, on_path, letters; };

// Walk 'rxe' (a root expression) and drive the visitor's callbacks. Node ids
// are assigned from zero in traversal order; the root is node zero.
void rxe_graph_walk(struct rxe *rxe, const struct rxe_graph_opts *opts,
                    const struct rxe_graph_visitor *v, void *ctx);

#endif // __RXE_GRAPH_H__
