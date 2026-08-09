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

// A keyed permutation of the integer mapping.
//
// The library already establishes a bijection between the integers and the
// members of a set. Composing it with a bijection from the integers to
// themselves gives another bijection, so the set can be walked in an order
// that depends on a key while every member is still visited exactly once.
// That is what makes this different from picking elements at random: a
// permutation cannot repeat itself and can be resumed from any index, so a
// brute force search can be randomised without becoming unrepeatable.
//
// The construction is a Feistel network over the index, with cycle walking to
// land back inside the range. The Feistel is a bijection on all b-bit values;
// re-applying it until the result falls below the set size restricts it to a
// bijection on exactly the members that exist.
//
// This is deliberately not a cipher. It is meant to spread the search order,
// not to withstand somebody who wants to work out the key.

#include "rxe.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------ Macro-Defined Constants ----------------------- */

#define RXE_PERMUTE_ROUNDS           8

/* -------------------------- Global Declarations ------------------------- */

struct rxe_permutation {
    mpz_t    domain;      // number of members; results always land below this
    size_t   half_bits;   // width of each Feistel half
    uint64_t key;
    int      rounds;
};

/* ---------------------------- Support Routines -------------------------- */

// splitmix64's finalising mixer. Cheap, and good enough to spread the rounds.

static uint64_t mix64(uint64_t z)
{
    z += 0x9E3779B97F4A7C15ULL;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

// The round function: absorbs one half of the index and squeezes out as many
// bits as the other half needs. Only has to be deterministic and well spread.

static void round_function(
    mpz_t out,
    uint64_t key,
    int round,
    const mpz_t in,
    size_t out_bits
) {
    uint64_t state = mix64(key ^ ((uint64_t)(round+1) * 0x9E3779B97F4A7C15ULL));

    size_t in_bytes = (mpz_sizeinbase(in,2) + 7) / 8;
    unsigned char *ibuf = malloc(in_bytes ? in_bytes : 1);
    size_t written = 0;
    if (!ibuf) { mpz_set_ui(out,0); return; }
    mpz_export(ibuf,&written,1,1,0,0,in);
    size_t i,j;
    for (i=0;i<written;i+=8) {
        uint64_t chunk = 0;
        for (j=0;j<8 && i+j<written;j++) chunk = (chunk<<8) | ibuf[i+j];
        state = mix64(state ^ chunk);
    }
    free(ibuf);

    size_t out_bytes = (out_bits + 7) / 8;
    unsigned char *obuf = malloc(out_bytes ? out_bytes : 1);
    if (!obuf) { mpz_set_ui(out,0); return; }
    for (i=0;i<out_bytes;i+=8) {
        uint64_t v = mix64(state ^ (uint64_t)(i/8 + 1));
        for (j=0;j<8 && i+j<out_bytes;j++) obuf[i+j] = (unsigned char)(v >> (8*j));
    }
    mpz_import(out,out_bytes,1,1,0,0,obuf);
    free(obuf);

    mpz_fdiv_r_2exp(out,out,out_bits);   // trim to exactly one half's width
}

// One pass of the Feistel network. A bijection on [0, 2^(2*half_bits)).
// Safe to call with 'out' and 'in' the same variable: both halves are taken
// out of 'in' before anything is written back.

static void feistel(mpz_t out, struct rxe_permutation *perm, const mpz_t in)
{
    mpz_t l,r,f,t;
    mpz_init(l); mpz_init(r); mpz_init(f); mpz_init(t);
    mpz_fdiv_q_2exp(l,in,perm->half_bits);   // high half
    mpz_fdiv_r_2exp(r,in,perm->half_bits);   // low half
    int i;
    for (i=0;i<perm->rounds;i++) {
        round_function(f,perm->key,i,r,perm->half_bits);
        mpz_xor(t,l,f);
        mpz_set(l,r);
        mpz_set(r,t);
    }
    mpz_mul_2exp(out,l,perm->half_bits);
    mpz_add(out,out,r);
    mpz_clear(l); mpz_clear(r); mpz_clear(f); mpz_clear(t);
}

/* ------------------------------------------------------------------------ */

// Folds a key string down to the 64 bits the round function uses. The key
// space is 2^64 whatever the caller passes; that is ample for choosing a
// search order, and no claim is made beyond that.

static uint64_t key_from_string(const char *key)
{
    uint64_t k = 0xCBF29CE484222325ULL;
    if (key) for (; *key; key++) k = mix64(k ^ (unsigned char)*key);
    return k;
}

struct rxe_permutation *rxe_permutation_new(const mpz_t domain, const char *key)
{
    if (mpz_sgn(domain) <= 0) return NULL;
    struct rxe_permutation *perm = NEW(1,struct rxe_permutation);
    mpz_init_set(perm->domain,domain);
    // Round the width up so both halves are equal. That makes the Feistel
    // domain at most four times the set size, so cycle walking terminates
    // after a couple of passes on average.
    perm->half_bits = (mpz_sizeinbase(domain,2) + 1) / 2;
    if (perm->half_bits < 1) perm->half_bits = 1;
    perm->key    = key_from_string(key);
    perm->rounds = RXE_PERMUTE_ROUNDS;
    return perm;
}

void rxe_permutation_free(struct rxe_permutation *perm)
{
    if (!perm) return;
    mpz_clear(perm->domain);
    rxe_mem_free(perm);
}

// Maps one index to another. 'index' must be in [0, domain); the result is a
// permutation of that same range, so feeding in 0..domain-1 yields every
// value exactly once.

void rxe_permutation_map(
    mpz_t result,
    struct rxe_permutation *perm,
    const mpz_t index
) {
    if (!perm) { mpz_set(result,index); return; }
    // With one member there is nowhere to permute to, and cycle walking would
    // have to go all the way round its cycle to discover that.
    if (mpz_cmp_ui(perm->domain,1) <= 0) { mpz_set_ui(result,0); return; }
    // The permutation is defined only on [0, domain). An index past the set --
    // a caller paging beyond the end -- has no image: the Feistel is a
    // bijection on its own power-of-two domain, so cycle walking from a value
    // the set does not contain can loop without ever falling below domain.
    // Return it unchanged rather than spin; a seek at that index then reports
    // past-the-end as it should.
    if (mpz_cmp(index,perm->domain) >= 0) { mpz_set(result,index); return; }
    mpz_set(result,index);
    do {
        feistel(result,perm,result);
    } while (mpz_cmp(result,perm->domain) >= 0);
}

/* ----------------------- Per-subexpression shuffle ---------------------- */

// A duplicate of a permutation, for cloning a group that carries one. The key
// and the shape are all it needs; nothing is derived from a string again.

struct rxe_permutation *rxe_permutation_clone(const struct rxe_permutation *perm)
{
    if (!perm) return NULL;
    struct rxe_permutation *copy = NEW(1,struct rxe_permutation);
    mpz_init_set(copy->domain,perm->domain);
    copy->half_bits = perm->half_bits;
    copy->key       = perm->key;
    copy->rounds    = perm->rounds;
    return copy;
}

// Turn a subexpression node into one whose members come out permuted by a key.
// The permutation is over the group's own cardinality, so it reorders those
// members among themselves and nothing else. An empty group has nothing to
// permute and gets no permutation, which rxe_permutation_map reads as the
// identity.

void rxe_shuffle_make(struct rxe_node *node, const char *key, int keylen)
{
    char *k = NEW(keylen+1,char);
    if (keylen) memcpy(k,key,keylen);
    k[keylen] = 0;
    node->is_shuffle = 1;
    node->shuffle    = rxe_permutation_new(node->rxe->nitems,k);
    rxe_mem_free(k);
    mpz_set(node->nitems,node->rxe->nitems);
    mpz_set_ui(node->comb_index,0);
    if (mpz_sgn(node->nitems) > 0) {
        mpz_t z;
        mpz_init_set_ui(z,0);
        rxe_shuffle_seek(node,z);
        mpz_clear(z);
    }
}

// Position the group at index 'pos' in its permuted order: map the index
// through the key, then seek the subexpression to the result.

int rxe_shuffle_seek(struct rxe_node *node, const mpz_t pos)
{
    mpz_t mapped;
    mpz_init(mapped);
    rxe_permutation_map(mapped,node->shuffle,pos);
    int rc = rxe_seek(node->rxe,mapped);
    mpz_set(node->comb_index,pos);
    mpz_clear(mapped);
    return rc;
}

// Step to the next member in permuted order, wrapping with a carry-out of 1.

int rxe_shuffle_iterate(struct rxe_node *node)
{
    mpz_t next;
    int carry = 0;
    mpz_init(next);
    mpz_add_ui(next,node->comb_index,1);
    if (mpz_cmp(next,node->nitems) >= 0) { mpz_set_ui(next,0); carry = 1; }
    rxe_shuffle_seek(node,next);
    mpz_clear(next);
    return carry;
}

void rxe_shuffle_free(struct rxe_node *node)
{
    if (node->shuffle) rxe_permutation_free(node->shuffle);
    node->shuffle    = NULL;
    node->is_shuffle = 0;
}
