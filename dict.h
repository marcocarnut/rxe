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

#ifndef __RXE_DICT_H__
#define __RXE_DICT_H__

// The bracket-expression body of a POSIX class -- "0-9" for [:digit:] -- or
// NULL if the name is not one. Single-character classes expand to an ordinary
// character class, so they compose with everything already; only multi-word
// dictionaries need the node kind below.
const char *rxe_posix_class(const char *name, int len);

// Look a word dictionary up by name, resolving it if it has not been seen. On
// success returns 1 and points *words/*nwords at the registry's own copy,
// which the caller must not free. On a miss returns 0.
int rxe_lookup_dict(const char *name, int len, char ***words, int *nwords);

#endif // __RXE_DICT_H__
