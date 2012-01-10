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
 
#ifndef __RXE_BKREFTBL_H_
#define __RXE_BKREFTBL_H_

struct rxe_backref_table *rxe_backref_table_new(int size_hint);
void rxe_backref_table_add(struct rxe_backref_table *brt, struct rxe *rxe);
void rxe_backref_table_free(struct rxe_backref_table *brt);

#endif // __RXE_BKREFTBL_H__
