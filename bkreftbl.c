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
#include "bkreftbl.h"
#include <memory.h>

struct rxe_backref_table *rxe_backref_table_new(int size_hint)
{
    struct rxe_backref_table *brt;
    brt = NEW(1,struct rxe_backref_table);
    brt->nbackrefs = 0;
    brt->maxbackrefs = size_hint;
    brt->bkref = NEW(size_hint,struct rxe *);
    return brt;
}

void rxe_backref_table_free(struct rxe_backref_table *brt)
{
    rxe_mem_free(brt->bkref);
    rxe_mem_free(brt);
}

void rxe_backref_table_add(struct rxe_backref_table *brt, struct rxe *rxe)
{
    if (!brt) return;
    if (brt->nbackrefs == brt->maxbackrefs) {
        struct rxe **new_bkref;
        new_bkref = NEW(brt->nbackrefs*2,struct rxe *);
        int size = brt->nbackrefs*sizeof(struct rxe *);
        memcpy(new_bkref,brt->bkref,size);
        rxe_mem_free(brt->bkref);
        brt->bkref = new_bkref;
        brt->maxbackrefs *= 2; // Is doubling a good idea?
    }
    brt->bkref[brt->nbackrefs++] = rxe;
}


