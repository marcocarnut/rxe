/*
 * rxe_lay - decompose a finite regex-set into a positional odometer.
 *
 *          The interpreter walks the set member by member; a bruteforce wants
 *          the set as an odometer instead -- a run of "wheels", one per
 *          position, that a carry increments. This turns a compiled rxe into
 *          exactly that: a class or baked alternation per position, with the
 *          occasional super-wheel (a large variable-count repeat, or a
 *          combinatorial choice) standing in for a whole span of digits.
 *
 *          It is the analysis half that rxejit grew, lifted into the library so
 *          more than one back end can consume it. rxejit emits C and OpenCL from
 *          the wheels; the jsrxe crack tab emits WGSL. Neither concern lives
 *          here -- rxe_lay knows odometers, not code generators.
 *
 *          (C) 2011 Marco "Kiko" Carnut <kiko at postcogito dot org>
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2 of the License, or (at your option) any later
 * version.  See http://www.gnu.org/licenses/gpl-2.0.html for details.
 */
#ifndef RXE_LAY_H
#define RXE_LAY_H

#include "rxe.h"

#define MAXW     4096              // most positions an unrolled mask may have
#define ALT_CAP  65536             // most members a baked alternation may hold
#define REP_SUBW 64                // most fixed sub-wheels a loop repeat's body may hold

// One odometer wheel: n alternatives at 'base'. When every alternative is the
// same length it is fixed -- L bytes, alternative i at base + i*L, the fast
// case (a class is L==1). When they differ it is variable -- L is 0, and aoff[i]
// / alen[i] give alternative i's start and length in 'base'. A member's fixed
// wheels sit at compile-time offsets; a variable one makes the offsets of every
// wheel after it depend on the choice, so such members are rebuilt each step.
struct wheel { const char *base; int n; int L; const int *aoff; const int *alen; };

// The render is a sequence of ops, in member order. Usually just LAY the wheels;
// a backreference adds a COPY of an earlier group's bytes, bracketed by the
// OPEN/CLOSE that record where that group landed. Only these interleave the
// wheel-laying, so a pattern without backrefs is a plain run of LAYs.
enum { OP_LAY, OP_OPEN, OP_CLOSE, OP_COPY };
struct op { int kind; int arg; };   // arg = wheel index (LAY) or group id (rest)

// The running build: the wheels gathered so far, the render ops, the groups a
// backreference names (matched by their rxe pointer), and every buffer baked
// for an alternation -- all freed once the code is out.
struct build {
    struct wheel *w;
    int           nw;
    struct op    *ops;
    int           nops, cops;
    struct rxe  **gref;           // rxe pointers a backreference targets (pass 1)
    int           ngref;
    struct rxe  **grxe;           // groups opened so far, and their ids by index
    int           ngroup;
    int           has_backref;
    void        **bake;
    int           nbake, cbake;
    struct rxe   *root;            // the whole pattern, for a node's source span

    // A variable-count repeat X{a,b} too large to unroll: kept as a super-wheel
    // rather than baked into one giant wheel. pre = w[0..lr_at), post = the
    // wheels appended after; the body X is lr_nsw fixed sub-wheels laid lr_a..
    // lr_b times -- an odometer whose length grows, a base-(product of the
    // sub-wheels) number. Only one such repeat, and only fixed sub-wheels.
    int           lr_active, lr_at, lr_a, lr_b, lr_nsw;
    struct wheel  lr_sw[REP_SUBW];

    // An ordered permutation (re){{lo,hi!}}: every ordered choice of s of the
    // pool's n members for each size s in [lo,hi], sum_s P(n,s) of them, the
    // size blocks ascending. Like the loop repeat it is a super-wheel in the
    // odometer -- pre = w[0..perm_at), post = the wheels after -- and its digit
    // is a factorial-base number whose length (the size s) varies with the
    // index. A single size {{k!}} is lo==hi==k. The pool is one baked wheel.
    int           perm_active, perm_at, perm_lo, perm_hi;
    int           perm_ordered;   // 1 = permutations {{k!}}, 0 = combinations {{k}}
    int           perm_chop;      // {{...?}}: bytes to quell from the last item
    struct wheel  perm_pool;
};

// Gather the wheels for the whole pattern into 'b' (which need not be
// initialised). Returns the wheel count, or -1 with rxe_lay_reason() set. On
// success the caller frees the buffers with rxe_lay_free.
int rxe_lay_build(struct build *b, struct rxe *rxe);
void rxe_lay_free(struct build *b);

// Why the last rxe_lay_build declined (returned -1). Valid until the next call.
const char *rxe_lay_reason(void);

// A combinatorial choice's size-s block cardinality: P(n,s) ordered, C(n,s) not.
// Returns -1 if it exceeds 64 bits, else 0 with *out set. Shared with the back
// ends, which decode the same super-wheel digit.
int choose_block(int n, int s, int ordered, unsigned long long *out);

#endif
