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
 
#ifndef __RXE_NODE_H__
#define __RXE_NODE_H__

struct rxe_node *rxe_new_node(struct rxe_alt *alt);
void rxe_free_node_data(struct rxe_node *node);
void rxe_free_node(struct rxe_node *node);

#endif // __RXE_NODE_H__
