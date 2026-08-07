/*
 * librxe - a library for enumerating sets described by regexes, version 0.9
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

// Spreading one index across several infinite dimensions.
//
// A finite expression is a numeral: each position is a digit, and the radix
// is that position's cardinality. That construction needs every radix but the
// most significant to be finite, so it cannot carry two unbounded quantifiers
// -- "[0-9]+@[a-z]+" has two dimensions with no largest value between them,
// and place value would spend eternity in the first one without ever reaching
// the second.
//
// The Cantor pairing function is the standard way out. It walks the plane in
// diagonals -- (0,0), (0,1), (1,0), (0,2), (1,1), (2,0) -- so both
// coordinates grow together and every pair is reached after finitely many
// steps:
//
//     pair(x,y) = (x+y)(x+y+1)/2 + y
//
// More than two dimensions nest it, pairing the first coordinate with the
// pairing of the rest.
//
// The order this produces is a diagonal walk over the dimensions' indices,
// which is not quite shortest-string-first. The two coincide when each index
// is itself the length it contributes, which is the "a*b*" case: there the
// diagonals are exactly the lengths, and the enumeration comes out shortest
// first. When the repeated unit has more than one member -- "[ab]*[cd]*" --
// an index of n stands for a string of about log2(n) characters, so the
// diagonals slant across the lengths rather than following them. Every member
// is still reached in finite time, which is the property that matters; see
// the TODO for what a true shortlex order would cost.

#include "rxe.h"
#include "pair.h"

/* ------------------------------------------------------------------------ */

static void pair2(mpz_t out, const mpz_t x, const mpz_t y)
{
    mpz_t s;
    mpz_init(s);
    mpz_add(s,x,y);                 // s = x+y
    mpz_mul(out,s,s);               // out = s^2
    mpz_add(out,out,s);             // out = s^2+s = s(s+1)
    mpz_tdiv_q_2exp(out,out,1);     // out = s(s+1)/2
    mpz_add(out,out,y);
    mpz_clear(s);
}

// The inverse. z lies on diagonal w, the largest w with w(w+1)/2 <= z, which
// is floor((sqrt(8z+1)-1)/2); y is how far along that diagonal it sits.

static void unpair2(mpz_t x, mpz_t y, const mpz_t z)
{
    mpz_t w,t;
    mpz_init(w);
    mpz_init(t);
    mpz_mul_2exp(w,z,3);            // w = 8z
    mpz_add_ui(w,w,1);              // w = 8z+1
    mpz_sqrt(w,w);                  // integer square root, rounded down
    mpz_sub_ui(w,w,1);
    mpz_tdiv_q_2exp(w,w,1);         // w = (sqrt(8z+1)-1)/2
    mpz_mul(t,w,w);
    mpz_add(t,t,w);
    mpz_tdiv_q_2exp(t,t,1);         // t = w(w+1)/2, the start of diagonal w
    mpz_sub(y,z,t);
    mpz_sub(x,w,y);
    mpz_clear(w);
    mpz_clear(t);
}

// Spread 'index' across 'n' dimensions, writing them into out[0..n-1]. With
// one dimension this is the identity, which is the common case and is why
// nothing else has to special-case a single unbounded quantifier.

void rxe_unpair(mpz_t *out, int n, const mpz_t index)
{
    int i;
    if (n <= 0) return;
    mpz_t rest;
    mpz_init_set(rest,index);
    for (i=0;i<n-1;i++) {
        // Peel the leading coordinate off and carry the pairing of whatever
        // is left into the next round.
        unpair2(out[i],rest,rest);
    }
    mpz_set(out[n-1],rest);
    mpz_clear(rest);
}

// The inverse of rxe_unpair, folding n dimensions back into one index.

void rxe_pair(mpz_t index, mpz_t *in, int n)
{
    int i;
    if (n <= 0) { mpz_set_ui(index,0); return; }
    mpz_set(index,in[n-1]);
    for (i=n-2;i>=0;i--) pair2(index,in[i],index);
}
