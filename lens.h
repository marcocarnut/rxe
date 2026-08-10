/*
 * librxe - a library for enumerating sets described by regexes, version 1.0.0
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

#ifndef __RXE_LENS_H__
#define __RXE_LENS_H__

void rxe_lens_init(struct rxe_lens *lens);
void rxe_lens_free(struct rxe_lens *lens);

void rxe_lens_rxe(struct rxe *rxe, int L);
void rxe_lens_alt(struct rxe_alt *alt, int L);
void rxe_count_at_length(mpz_t out, struct rxe *rxe, int L);

int rxe_seek_at_length(struct rxe *rxe, int L, const mpz_t idx);
int rxe_seek_shortlex(struct rxe *rxe, const mpz_t pos);
int rxe_repeat_seek_at_length(struct rxe_node *node, int L, const mpz_t idx,
                              int l2r);

// The inverse of rxe_seek_shortlex: report every shortlex index at which the
// string s of length len sits, each handed to the visitor. A member may sit at
// more than one index when the set has duplicates. Returns 0 on success, or -1
// if the set is outside what shortlex rank handles yet -- a variable-length
// repetition body or left-to-right ordering -- in which case nothing is
// visited. The visitor returns non-zero to stop early.
typedef int (*rxe_rank_visit)(void *ctx, const mpz_t index);
int rxe_rank_shortlex(struct rxe *rxe, const char *s, int len,
                      rxe_rank_visit visit, void *ctx);

// Non-zero if this expression can match the empty string. An unbounded
// repetition of one derives the empty string infinitely many ways, so its
// count at length zero does not converge and the parser refuses it.
int rxe_matches_empty(struct rxe *rxe);

#endif // __RXE_LENS_H__
