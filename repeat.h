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

#ifndef __RXE_REPEAT_H__
#define __RXE_REPEAT_H__

void rxe_repeat_nitems(mpz_t out, const mpz_t base, int r0, int r1);
void rxe_repeat_make(struct rxe_node *node, int r0, int r1);
int  rxe_repeat_is_infinite(struct rxe_node *node);
int rxe_repeat_reserve(struct rxe_node *node, int want);
void rxe_repeat_free(struct rxe_node *node);
int  rxe_repeat_seek(struct rxe_node *node, const mpz_t pos, int l2r);
int  rxe_repeat_iterate(struct rxe_node *node, int l2r);

#endif // __RXE_REPEAT_H__
