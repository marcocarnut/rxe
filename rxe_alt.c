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
 
#include "rxe.h"
#include "rxe_alt.h"

struct rxe_alt *rxe_new_alt(struct rxe *rxe)
{
    struct rxe_alt *alt = NEW(1,struct rxe_alt);
    alt->head = NULL;
    alt->tail = NULL;
    alt->next = NULL;
    alt->prev = rxe->tail;
    mpz_init(alt->nitems);
    mpz_init(alt->start);
    rxe->nalts++;
    if (rxe->tail)  rxe->tail->next = alt;
    rxe->tail = alt;
    if (!rxe->head) rxe->head = alt;
    if (!rxe->curr) rxe->curr = alt;
    return alt;
}

void rxe_free_alt(struct rxe_alt *alt)
{
    struct rxe_node *node,*next;
    for ( node = alt->head ; node ; node = next ) {
        next = node->next;
        rxe_free_node(node);
    }
    mpz_clear(alt->start);
    mpz_clear(alt->nitems);
    rxe_mem_free(alt);
}
