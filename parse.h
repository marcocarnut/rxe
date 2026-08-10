/*
 * librxe - a library for enumerating sets described by regexes, version 1.1.0
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

#ifndef __RXE_PARSE_H__
#define __RXE_PARSE_H__

// Include rxe.h before this header. rxe_parse() in rxe.c is the public entry
// point; this declares the recursive worker it calls, which was previously
// reached through an implicit declaration.

const char *parse(struct rxe *rxe, mpz_t ret, const char *str, int flags,
                  int depth, const char *base);

#endif // __RXE_PARSE_H__
