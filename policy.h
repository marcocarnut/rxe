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

#ifndef POLICY_H
#define POLICY_H

#include "rxe.h"

// The cardinality of a policy composition: every length lo..hi string over the
// disjoint union of the base alternation's k branches, with branch i appearing
// at least floors[i] times. 'base' is the alternation (node->rxe); its branch
// cardinalities are the s_i. Computed by a dynamic program over lengths, so no
// count-vector is ever enumerated.
void rxe_policy_nitems(mpz_t out, struct rxe *base, int lo, int hi,
                       const int *floors, int nfloors);

// Turn 'node' into a policy composition over its subexpression's branches. The
// caller has already put the base alternation into node->rxe and validated that
// nfloors equals the branch count and that every branch is width 1. 'soaker' is
// the index of the '+' branch (the surplus absorber for the minimal-first
// enumeration order), or -1. Sets node->nitems.
void rxe_policy_make(struct rxe_node *node, int lo, int hi,
                     const int *floors, int nfloors, int soaker);

int rxe_policy_seek(struct rxe_node *node, const mpz_t pos);
int rxe_policy_iterate(struct rxe_node *node);

// Lay out the policy's segments -- one per (length, count-vector) block, in the
// minimal-compliance-first order -- for the code generators, which decode a
// 64-bit index over the baked table. 's' holds the k branch cardinalities;
// 'soaker0' is the '+' branch or -1 (defaults to the last). Fills seg_L[i], the
// count vector seg_cv[i*k + t], and the cumulative offset seg_off[i] for i in
// [0, nseg); seg_off[nseg] is the grand total. Returns the segment count, or -1
// (with *why set) when the total exceeds 64 bits or there are more than 'cap'
// segments. The caller sizes seg_L/seg_off to cap+1 and seg_cv to (cap+1)*k.
int rxe_policy_segments(const unsigned long *s, int k, int lo, int hi,
                        const int *floors, int soaker0, int cap,
                        int *seg_L, int *seg_cv, unsigned long long *seg_off,
                        const char **why);

// The local index of a member from its decomposition: cls[p] is the branch that
// position p belongs to, cidx[p] the character chosen within that branch. The
// exact inverse of the seek, used by rank to turn a member back into its index.
void rxe_policy_local(struct rxe_node *node, const int *cls, const int *cidx,
                      int L, mpz_t out);

#endif
