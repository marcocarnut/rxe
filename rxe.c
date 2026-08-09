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
 
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "rxe.h"
#include "rxe_alt.h"
#include "rxe_node.h"
#include "bkreftbl.h"
#include "repeat.h"
#include "comb.h"
#include "pair.h"
#include "lens.h"
#include "parse.h"

/* ------------------------ Macro-Defined Constants ----------------------- */

/* -------------------------- Global Declarations ------------------------- */

int rxe_initialized;

void *(*rxe_mem_alloc)(size_t);
void (*rxe_mem_free)(void *);
void (*rxe_mem_alloc_failed)(size_t size, const char *file, int line);

/* -------------------------- Function Prototypes ------------------------- */

void kmalloc_failed(size_t size, const char *file, int line);

void rxe_set_alloc(
    void * (*malloc_func)(size_t),
    void (*free_func)(void *),
    void (*fail_func)(size_t size, const char *file, int line)
);

/* ------------------------------------------------------------------------ */

void rxe_init(void)
{
    rxe_initialized = 1;
    rxe_set_alloc(malloc,free,kmalloc_failed);
}

void rxe_set_alloc(
    void * (*malloc_func)(size_t),
    void (*free_func)(void *),
    void (*fail_func)(size_t size, const char *file, int line)
)
{
    rxe_mem_alloc = malloc_func;
    rxe_mem_free = free_func;
    rxe_mem_alloc_failed = fail_func;
    // Counts as initialising. Without this, a caller who installed its own
    // allocator had it quietly replaced by the default one the first time
    // rxe_parse ran, which made the whole hook pointless.
    rxe_initialized = 1;
}

// Returns the first alternation that contributes any string at all. An
// alternation whose product is zero holds an impossible node -- an empty
// character class, say -- and matches nothing, so enumeration must step over
// it. This is distinct from an alternation with no nodes, whose product is
// one because it matches the empty string.

static struct rxe_alt *rxe_first_alt(struct rxe *rxe)
{
    struct rxe_alt *alt;
    for ( alt = rxe->head ; alt ; alt = alt->next )
        if (mpz_sgn(alt->nitems)) return alt;
    return NULL;
}

int rxe_is_infinite(struct rxe *rxe)
{
    return rxe && rxe->ninf > 0;
}

int rxe_is_shortlex(struct rxe *rxe)
{
    return rxe && (rxe->flags & RXE_FLAG_SHORTLEX) != 0;
}

// A backreference's length is whatever the group it names turned out to be,
// so the positions of a concatenation stop being independent and the
// convolution the length counts are built from no longer describes the set.
// Rather than refuse such an expression, it keeps the diagonal order.

static int tree_has_backref(struct rxe *rxe)
{
    struct rxe_alt *alt;
    struct rxe_node *node;
    for ( alt = rxe->head ; alt ; alt = alt->next )
        for ( node = alt->head ; node ; node = node->next ) {
            // Do not follow a backreference: it points at a group owned
            // elsewhere in the tree, and following it would go round in
            // circles.
            if (node->is_backref) return 1;
            // A combination or permutation is a finite choice with an order of
            // its own, not a length-countable concatenation, so it keeps the
            // diagonal order too rather than being enumerated shortest first.
            if (node->is_comb) return 1;
            // A shuffled group scrambles which member sits at which index, so
            // its lengths can no longer be counted in enumeration order either.
            if (node->is_shuffle) return 1;
            if (node->rxe && tree_has_backref(node->rxe)) return 1;
        }
    return 0;
}

static void mark_shortlex(struct rxe *rxe)
{
    struct rxe_alt *alt;
    struct rxe_node *node;
    rxe->flags |= RXE_FLAG_SHORTLEX;
    for ( alt = rxe->head ; alt ; alt = alt->next )
        for ( node = alt->head ; node ; node = node->next )
            if (node->rxe && !node->is_backref) mark_shortlex(node->rxe);
}

// The i-th alternation that has no largest member, counted in written order.

static struct rxe_alt *rxe_nth_inf_alt(struct rxe *rxe, unsigned long i)
{
    struct rxe_alt *alt;
    for ( alt = rxe->head ; alt ; alt = alt->next )
        if (alt->ninf && !i--) return alt;
    return NULL;
}

char *rxe_current(char *str, int maxlen, struct rxe *rxe)
{
    if (maxlen<=0) return str;
    str[0] = 0;
    struct rxe_alt *alt = rxe->curr;
    struct rxe_node *node;
    if (!alt) return str;
    for ( node = alt->head ; node ; node = node->next ) {
        if (node->is_repeat || node->is_comb) {
            // One copy of the subexpression stands in for every position, so
            // it has to be seeked to each position's index in turn. Rendering
            // in string order also means the subexpression is left holding the
            // final repetition, which is what a later backreference into it
            // should see. The digits are stored by position rather than by
            // significance, so this walks them in string order whichever way
            // round the odometer runs.
            int i;
            int shortlex = rxe->flags & RXE_FLAG_SHORTLEX;
            for ( i = 0 ; i < node->rep_count ; i++ ) {
                char *new_str;
                // An unbounded repetition can select a run far longer than
                // the caller's buffer -- 'a*' at index a billion is a billion
                // characters -- so stop as soon as there is no room, rather
                // than generating the rest of it to throw away.
                if (maxlen <= 0) break;
                // Addressed by the length it takes and its place among the
                // members of that length, rather than by one index into the
                // body's whole ordering, which an endless body does not have
                // in a useful order.
                if (shortlex
                        ? rxe_seek_at_length(node->rxe,node->rep_len[i],
                                             node->rep_digit[i])
                        : rxe_seek(node->rxe,node->rep_digit[i])) break;
                new_str = rxe_current(str,maxlen,node->rxe);
                maxlen -= new_str - str;
                str = new_str;
            }
        } else if (node->rxe) {
            char *new_str = rxe_current(str,maxlen,node->rxe);
            maxlen -= new_str - str;
            str = new_str;
        } else if (node->is_dict) {
            // A dictionary member is a whole word, not a character. Copy as
            // much of it as the buffer still holds.
            const char *w = node->words[node->iterator];
            while (*w && maxlen>0) { *str++ = *w++; maxlen--; }
        } else if (node->len) {
            // A node with no characters has nothing to contribute. Indexing
            // its str would read past a zero-length allocation.
            if (maxlen>0) {
                *str++ = node->str[node->iterator];
                maxlen--;
            }
        }
    }
    *str = 0;
    return str;
}

int rxe_iterate(struct rxe *rxe)
{
    if (!rxe || !rxe->curr) return 1;
    if (rxe->ninf) {
        // No odometer walks this. The order over the endless dimensions is a
        // diagonal, not place value, so the only way to step is to address
        // the next index and seek to it. There is always a next one, which is
        // why an infinite expression never carries out.
        mpz_add_ui(rxe->index,rxe->index,1);
        return rxe_seek(rxe,rxe->index);
    }
    struct rxe_alt *alt = rxe->curr;
    // Which end of the alternation carries first: the last node is the least
    // significant digit by default, so that enumeration counts the way an
    // ordinary numeral does.
    int l2r = rxe->flags & RXE_FLAG_LEFT_TO_RIGHT;
    struct rxe_node *node = l2r ? alt->head : alt->tail;
    int carry = 1;
    if (node) {
        while (carry) {
            if (node->is_repeat) {
                carry = rxe_repeat_iterate(node,l2r);
            } else if (node->is_comb) {
                carry = rxe_comb_iterate(node);
            } else if (node->is_shuffle) {
                carry = rxe_shuffle_iterate(node);
            } else if (node->rxe && !node->is_backref) {
                carry = rxe_iterate(node->rxe);
            }
            if (carry) {
                int bound = node->is_dict ? node->nwords : node->len;
                if (++node->iterator >= bound) {
                    node->iterator = 0;
                    node = l2r ? node->next : node->prev;
                    if (!node) break;
                } else {
                    carry = 0;
                }
            }
        }
    }
    if (carry) {
        do { alt = alt->next; } while (alt && !mpz_sgn(alt->nitems));
        if (alt) {
            rxe->curr = alt;
            carry = 0;
        } else {
            rxe->curr = rxe_first_alt(rxe);
        }
    }
    return carry;
}

// Select the item at 'pos' within one alternation.
//
// The finite positions are the digits of a numeral, as they always were.
// Positions with no largest member cannot be digits -- place value needs
// every radix but the most significant to be finite -- so they are lifted out
// above the numeral and the leftover is spread across them by a pairing
// function. With one such position, which is much the commonest case, that
// spreading is the identity and this is the old code with the division done
// one step earlier.

static int rxe_alt_seek(struct rxe_alt *alt, const mpz_t pos, int l2r)
{
    struct rxe_node *node;
    mpz_t *dim = NULL;
    mpz_t q,r,n,p;
    int rc = 0, i = 0;
    mpz_init(q);
    mpz_init(r);
    mpz_init(n);
    mpz_init_set(p,pos);
    if (alt->ninf) {
        // alt->nitems counts the finite positions only, and is at least one
        // because an empty product is one, so this division is always safe.
        mpz_tdiv_qr(q,p,p,alt->nitems);
        dim = NEW(alt->ninf,mpz_t);
        for (i=0;i<alt->ninf;i++) mpz_init(dim[i]);
        rxe_unpair(dim,alt->ninf,q);
        i = 0;
    }
    for ( node = l2r ? alt->head : alt->tail ; node ;
          node = l2r ? node->next : node->prev ) {
        if (node->is_backref) continue;
        if (node->is_inf) {
            // Takes a whole dimension rather than a digit's worth of the
            // numeral, so no division happens here. The dimensions are handed
            // out in order of significance, most significant first, because
            // the pairing walks its diagonals with the first coordinate
            // descending: giving that one to the most significant position
            // makes 'a*b*' come out shortest first and alphabetically within
            // a length -- "", a, b, aa, ab, bb -- which is the order the
            // finite case would have produced had it been able to reach it.
            mpz_t *d = &dim[alt->ninf-1-i];
            if (node->is_repeat ? rxe_repeat_seek(node,*d,l2r)
                                : rxe_seek(node->rxe,*d)) { rc = 1; break; }
            i++;
            continue;
        }
        // A repetition or a combination is a node whose cardinality is not its
        // subexpression's: the geometric sum for one, the binomial sum for the
        // other. Both carry their own count in node->nitems.
        mpz_set(n, node->rxe && !node->is_repeat && !node->is_comb
                       ? node->rxe->nitems : node->nitems);
        // An impossible node cannot be indexed into. Alternations holding one
        // are skipped by the caller, so reaching this means the caller seeked
        // into a set that has no such element; report failure rather than
        // abort.
        if (!mpz_sgn(n)) { rc = 1; break; }
        mpz_tdiv_qr(q,r,p,n);
        mpz_set(p,q);
        if (node->is_repeat) {
            if (rxe_repeat_seek(node,r,l2r)) { rc = 1; break; }
        } else if (node->is_comb) {
            if (rxe_comb_seek(node,r)) { rc = 1; break; }
        } else if (node->is_shuffle) {
            if (rxe_shuffle_seek(node,r)) { rc = 1; break; }
        } else if (node->rxe) {
            rxe_seek(node->rxe,r);
        } else {
            node->iterator = mpz_get_ui(r);
        }
    }
    // Whatever the numeral could not absorb is an index past the last item.
    // An alternation with an endless position has no last item, and its
    // leftover went into the pairing rather than staying here.
    if (!rc && mpz_sgn(p) > 0) rc = 1;
    if (dim) {
        for (i=0;i<alt->ninf;i++) mpz_clear(dim[i]);
        rxe_mem_free(dim);
    }
    mpz_clear(q);
    mpz_clear(r);
    mpz_clear(n);
    mpz_clear(p);
    return rc;
}

int rxe_seek(struct rxe *rxe, mpz_t pos)
{
    if (!rxe || mpz_sgn(pos) < 0) return 1;
    if (rxe->flags & RXE_FLAG_SHORTLEX) {
        int rc = rxe_seek_shortlex(rxe,pos);
        if (!rc) mpz_set(rxe->index,pos);
        return rc;
    }
    struct rxe_alt *alt = NULL;
    int l2r = rxe->flags & RXE_FLAG_LEFT_TO_RIGHT;
    int rc;
    mpz_t p;
    mpz_init_set(p,pos);
    if (rxe->ninf && mpz_cmp(pos,rxe->nitems) >= 0) {
        // Past every finite alternation, so this is one of the endless ones.
        // They are dovetailed rather than laid end to end: consecutive
        // indices visit them in turn, because laying them end to end would
        // mean the second never started.
        mpz_t which;
        mpz_init(which);
        mpz_sub(p,pos,rxe->nitems);
        mpz_tdiv_qr_ui(p,which,p,(unsigned long)rxe->ninf);
        alt = rxe_nth_inf_alt(rxe,mpz_get_ui(which));
        mpz_clear(which);
    } else {
        // A linear scan, which is slow when an expression has a great many
        // alternations. It used to be the obvious thing to replace with a
        // binary search, because a repetition wrote out one alternation per
        // repeat count and so manufactured them by the thousand. Repetitions
        // are counted rather than written out now, and hand-written
        // alternations do not run to those numbers: 20,000 of them still seek
        // in 0.02s. See the TODO.
        for ( alt = rxe->tail ; alt ; alt = alt->prev ) {
            if (alt->ninf) continue;               // indexed above, not here
            if (!mpz_sgn(alt->nitems)) continue;   // matches nothing; skip it
            if (mpz_cmp(alt->start,pos)<=0) { mpz_sub(p,p,alt->start); break; }
        }
    }
    if (!alt) { mpz_clear(p); return 1; }
    rc = rxe_alt_seek(alt,p,l2r);
    if (!rc) {
        rxe->curr = alt;
        mpz_set(rxe->index,pos);
    }
    mpz_clear(p);
    return rc;
}

struct rxe *rxe_parse(const char *str, int flags)
{
    if (!rxe_initialized) rxe_init();
    struct rxe *rxe = rxe_new();
    rxe->brt = rxe_backref_table_new(10);
    rxe->flags |= RXE_FLAG_HAS_BKRTABLE;
    if (*str=='^') str++;
    parse(rxe,rxe->nitems,str,flags,0);
    // Only an infinite expression is enumerated by length; a finite one is a
    // numeral and keeps the order it has always had, which the radix
    // conversion in the manual page depends on.
    if (!rxe->status && rxe_is_infinite(rxe) && !tree_has_backref(rxe))
        mark_shortlex(rxe);
    return rxe;
}

struct rxe *rxe_new(void)
{

    struct rxe *rxe = NEW(1,struct rxe);
    rxe->head = rxe-> tail = rxe->curr = NULL;
    rxe->nalts = 0;
    rxe->ninf = 0;
    rxe->status = RXE_OK;
    rxe->brt = NULL;
    rxe->flags = 0;
    mpz_init(rxe->nitems);
    mpz_init(rxe->index);
    rxe_lens_init(&rxe->lens);
    return rxe;
}

// The 'shallow' argument this used to take made the copy alias the original
// subexpression rather than duplicating it, with ownership passing to whichever
// of the two was reached first. Only the written-out repetition needed that,
// and it no longer exists; nothing else could use it safely.

void rxe_node_deep_clone(struct rxe_alt *alt, struct rxe_node *src_node)
{
    struct rxe_node *dst_node = rxe_new_node(alt);
    if (src_node->rxe) {
        // A backreference names a subexpression owned elsewhere, so the copy
        // points at the same one rather than duplicating it.
        dst_node->rxe = src_node->is_backref ? src_node->rxe
                                             : rxe_deep_clone(src_node->rxe);
    }
    if (src_node->len) {
        dst_node->len = src_node->len;
        assert(src_node->len<256);
        dst_node->str = NEW(dst_node->len,char);
        memcpy(dst_node->str,src_node->str,dst_node->len);
    }
    dst_node->is_backref = src_node->is_backref;
    dst_node->is_inf     = src_node->is_inf;
    // A dictionary node borrows its words, so the copy borrows the same ones.
    dst_node->is_dict    = src_node->is_dict;
    dst_node->nwords     = src_node->nwords;
    dst_node->words      = src_node->words;
    mpz_set(dst_node->nitems,src_node->nitems);
    if (src_node->is_repeat) {
        // rxe_repeat_make recomputes nitems from the subexpression, so the
        // copy above is redundant here but harmless, and the clone starts at
        // the first item rather than wherever the original happens to sit.
        rxe_repeat_make(dst_node,src_node->rep_min,src_node->rep_max);
    } else if (src_node->is_comb) {
        // Likewise a combination is rebuilt from its subexpression and size
        // range, starting at its first choice.
        rxe_comb_make(dst_node,src_node->rep_min,src_node->rep_max,
                      src_node->comb_perm);
    } else if (src_node->is_shuffle) {
        // A shuffled group carries the same key; clone the permutation and
        // start it at its first member.
        dst_node->is_shuffle = 1;
        dst_node->shuffle = rxe_permutation_clone(src_node->shuffle);
        mpz_set_ui(dst_node->comb_index,0);
        mpz_t z;
        mpz_init_set_ui(z,0);
        rxe_shuffle_seek(dst_node,z);
        mpz_clear(z);
    }
}

struct rxe *rxe_deep_clone(struct rxe *src_rxe)
{
   struct rxe *dst_rxe = rxe_new();
   struct rxe_alt *src_alt;
   // Carry the subexpression's own flags across -- the enumeration direction
   // among them -- but never the ownership bit: only the root owns the
   // backreference table, and this clone has none to free.
   dst_rxe->flags = src_rxe->flags & ~RXE_FLAG_HAS_BKRTABLE;
   dst_rxe->ninf  = src_rxe->ninf;
   mpz_set(dst_rxe->nitems,src_rxe->nitems);
   for ( src_alt = src_rxe->head ; src_alt ; src_alt = src_alt->next ) {
       struct rxe_alt *dst_alt = rxe_new_alt(dst_rxe);
       dst_alt->ninf = src_alt->ninf;
       mpz_set(dst_alt->nitems,src_alt->nitems);
       mpz_set(dst_alt->start,src_alt->start);
       struct rxe_node *src_node;
       for ( src_node = src_alt->head ; src_node ; src_node = src_node->next ) {
           rxe_node_deep_clone(dst_alt,src_node);
       }
   }
   return dst_rxe;
}

void rxe_free(struct rxe *rxe)
{
    struct rxe_alt *alt,*next;
    for ( alt = rxe->head ; alt ; alt = next ) {
        next = alt->next;
        rxe_free_alt(alt);
    }
    if (rxe->flags & RXE_FLAG_HAS_BKRTABLE)
        rxe_backref_table_free(rxe->brt);
    mpz_clear(rxe->nitems);
    mpz_clear(rxe->index);
    rxe_lens_free(&rxe->lens);
    rxe_mem_free(rxe);
}

/* ---------------------------- Support Routines -------------------------- */

void *kmalloc(size_t size, const char *file, int line)
{
    // Any public entry point can be the first one called -- creating a
    // permutation before parsing anything, for instance -- so the allocator
    // has to be in place here rather than only in rxe_parse.
    if (!rxe_initialized) rxe_init();
    void *p = rxe_mem_alloc(size);
    if (p) return p;
    // The hook is expected not to return, but nothing enforces that, and
    // falling off the end of a non-void function is undefined behaviour.
    if (rxe_mem_alloc_failed) rxe_mem_alloc_failed(size,file,line);
    return NULL;
}

void kmalloc_failed(size_t size, const char *file, int line)
{
    fprintf(stderr,"Can't get %d bytes of memory at %s line %d.",
        (int)size,file,line);
    exit(111);
}

