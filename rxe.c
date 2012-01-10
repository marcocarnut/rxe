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
 
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "rxe.h"
#include "rxe_alt.h"
#include "rxe_node.h"
#include "bkreftbl.h"

/* ------------------------ Macro-Defined Constants ----------------------- */

#define ENUM_ONCE                    1
#define ENUM_NUMBER                  2

#define RXE_FLAG_HAS_BKRTABLE        2

/* -------------------------- Global Declarations ------------------------- */

int rxe_initialized;

void *(*rxe_mem_alloc)(size_t);
void (*rxe_mem_free)(void *);
void (*rxe_mem_alloc_failed)(size_t size, char *file, int line);

/* -------------------------- Function Prototypes ------------------------- */

void rxe_node_deep_clone(struct rxe_alt *alt, struct rxe_node *src_node, int shallow);
struct rxe *rxe_deep_clone(struct rxe *src_rxe);

void kmalloc_failed(size_t size, char *file, int line);

void rxe_set_alloc(
    void * (*malloc_func)(size_t),
    void (*free_func)(void *),
    void (*fail_func)(size_t size, char *file, int line)
);

/* ------------------------------------------------------------------------ */

void rxe_init(void)
{
    int n;
    rxe_initialized = 1;
    rxe_set_alloc(malloc,free,kmalloc_failed);
}

void rxe_set_alloc(
    void * (*malloc_func)(size_t),
    void (*free_func)(void *),
    void (*fail_func)(size_t size, char *file, int line)
)
{
    rxe_mem_alloc = malloc_func;
    rxe_mem_free = free_func;
    rxe_mem_alloc_failed = fail_func;
}

char *rxe_current(char *str, int maxlen, struct rxe *rxe)
{
    if (maxlen<=0) return;
    str[0] = 0;
    struct rxe_alt *alt = rxe->curr;
    struct rxe_node *node;
    for ( node = alt->head ; node ; node = node->next ) {
        if (node->rxe) {
            char *new_str = rxe_current(str,maxlen,node->rxe);
            maxlen -= new_str - str;
            str = new_str;
        } else {
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
    struct rxe_alt *alt = rxe->curr;
    if (!alt) return 1;
    struct rxe_node *node = alt->tail;
    int carry = 1;
    if (node) {
        while (carry) {
            if (node->rxe && !node->is_backref) {
                carry = rxe_iterate(node->rxe);
            }
            if (carry) {
                if (++node->iterator >= node->len) {
                    node->iterator = 0;
                    node = node->prev;
                    if (!node) break;
                } else {
                    carry = 0;
                }
            }
        }
    }
    if (carry) {
        alt = alt->next;
        if (alt) {
            rxe->curr = alt;
            carry = 0;
        } else {
            rxe->curr = rxe->head;
        }
    }
    return carry;
}

int rxe_seek(struct rxe *rxe, mpz_t pos)
{
    if (!rxe) return;
    mpz_t q,r,p,n;
    mpz_init(q);
    mpz_init(r);
    mpz_init(n);
    mpz_init_set(p,pos);
    struct rxe_alt *alt;
    struct rxe_node *node = NULL;
    // FIXME: Performance: this is slow if the number of alternations is large.
    // We should enumerate this into an array and binary search it instead.
    // Also, as an enhancement, we should add a flag to allow left-to-right
    // instead of right-to-left associativity. This should be done on each
    // subexpression so we can fine tune the order in which the sets will be
    // enumerated.
    for ( alt = rxe->tail ; alt ; alt = alt->prev ) {
        if (mpz_cmp(alt->start,pos)<=0) {
            rxe->curr = alt;
            node = alt->tail;
            mpz_sub(p,p,alt->start);
            break;
        }
    }
    for ( ; node ; node = node->prev ) {
        if (node->is_backref) continue;
        mpz_set(n, node->rxe ? node->rxe->nitems : node->nitems);
        assert(mpz_sgn(n)!=0);
        mpz_tdiv_qr(q,r,p,n);
        mpz_set(p,q);
        if (node->rxe) {
            rxe_seek(node->rxe,r);
            mpz_set(n,node->rxe->nitems);
        } else {
            node->iterator = mpz_get_ui(r);
        }
    }
    if (mpz_sgn(q)>0 && mpz_cmp_ui(n,1)>0 || mpz_sgn(p)>0) 
        return 1;
    return 0;
}

struct rxe *rxe_parse(char *str, int flags)
{
    if (!rxe_initialized) rxe_init();
    struct rxe *rxe = rxe_new();
    rxe->brt = rxe_backref_table_new(10);
    rxe->flags |= RXE_FLAG_HAS_BKRTABLE;
    if (*str=='^') str++;
    parse(rxe,rxe->nitems,str,flags,0);
    return rxe;
}

struct rxe *rxe_new(void)
{

    struct rxe *rxe = NEW(1,struct rxe);
    rxe->head = rxe-> tail = rxe->curr = NULL;
    rxe->nalts = 0;
    rxe->brt = NULL;
    rxe->flags = 0;
    mpz_init(rxe->nitems);
    return rxe;
}

void rxe_node_deep_clone(struct rxe_alt *alt, struct rxe_node *src_node, int shallow)
{
    struct rxe_node *dst_node = rxe_new_node(alt);
    if (src_node->rxe) {
        if (src_node->is_backref) {
            dst_node->rxe = src_node->rxe;
        } else {
            dst_node->rxe = shallow ? src_node->rxe : rxe_deep_clone(src_node->rxe);
        }
    }
    if (src_node->len) {
        dst_node->len = src_node->len;
        assert(src_node->len<256);
        dst_node->str = NEW(dst_node->len,char);
        memcpy(dst_node->str,src_node->str,dst_node->len);
    }
    dst_node->is_backref = src_node->is_backref;
    mpz_set(dst_node->nitems,src_node->nitems);
}

struct rxe *rxe_deep_clone(struct rxe *src_rxe)
{
   struct rxe *dst_rxe = rxe_new();
   struct rxe_alt *src_alt;
   mpz_set(dst_rxe->nitems,src_rxe->nitems);
   for ( src_alt = src_rxe->head ; src_alt ; src_alt = src_alt->next ) {
       struct rxe_alt *dst_alt = rxe_new_alt(dst_rxe);
       mpz_set(dst_alt->nitems,src_alt->nitems);
       mpz_set(dst_alt->start,src_alt->start);
       struct rxe_node *src_node;
       for ( src_node = src_alt->head ; src_node ; src_node = src_node->next ) {
           rxe_node_deep_clone(dst_alt,src_node,0);
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
    rxe_mem_free(rxe);
}

/* ---------------------------- Support Routines -------------------------- */

void *kmalloc(size_t size, char *file, int line)
{
    void *p = rxe_mem_alloc(size);
    if (p) return p;
    if (rxe_mem_alloc_failed) rxe_mem_alloc_failed(size,file,line);
}

void kmalloc_failed(size_t size, char *file, int line)
{
    fprintf(stderr,"Can't get %d bytes of memory at %s line %d.",
        (int)size,file,line);
    exit(111);
}

