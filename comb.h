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

#ifndef COMB_H
#define COMB_H

#include "rxe.h"

// The cardinality of choosing sizes lo..hi from a base of 'n' members:
// sum over the sizes of C(n,size) when perm is 0, or P(n,size) when perm is 1.
void rxe_comb_nitems(mpz_t out, const mpz_t n, int lo, int hi, int perm);

// Turn 'node' into a combination (perm 0) or permutation (perm 1) over its
// subexpression, choosing between lo and hi of its members. The caller has
// already put the base into node->rxe. Sets node->nitems.
void rxe_comb_make(struct rxe_node *node, int lo, int hi, int perm);

// Select the choice at linear index 'pos'. Returns 1 if pos is past the end.
int rxe_comb_seek(struct rxe_node *node, const mpz_t pos);

// Step to the next choice, wrapping to the first with a carry-out of 1.
int rxe_comb_iterate(struct rxe_node *node);

#endif
