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

struct rxe_node *rxe_new_node(struct rxe_alt *alt)
{
    struct rxe_node *node = NEW(1,struct rxe_node);
    node->next = NULL;
    node->prev = alt->tail;
    mpz_init(node->nitems);
    mpz_init(node->start);
    node->len = node->iterator = 0;
    node->is_backref = 0;
    node->str = NULL;
    node->rxe = NULL;
    alt->nnodes++;
    if (alt->tail) alt->tail->next = node;
    alt->tail = node;
    if (!alt->head) alt->head = node;
    if (!alt->curr) alt->curr = node;
    return node;
}

void rxe_free_node_data(struct rxe_node *node)
{
    // A backreference node only aliases the subexpression it refers to; the
    // node that parsed that subexpression owns it and will free it. Freeing
    // it here too would be a double free.
    if (node->rxe) {
        if (!node->is_backref) rxe_free(node->rxe);
        node->rxe = NULL;
    }
    // Keyed off the pointer, not the length: an empty character class still
    // allocates a (zero-length) block, and testing len left it behind.
    if (node->str) {
        rxe_mem_free(node->str);
        node->len = 0;
        node->str = NULL;
    }
}

void rxe_free_node(struct rxe_node *node)
{
    rxe_free_node_data(node);
    // rxe_new_node initialises both of these, so both have to be released
    // here, exactly as rxe_free_alt does for the alternation's own pair.
    mpz_clear(node->nitems);
    mpz_clear(node->start);
    rxe_mem_free(node);
}


