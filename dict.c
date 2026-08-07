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

// Named dictionaries, written [:name:].
//
// Two kinds share the one syntax. A POSIX class -- [:alpha:], [:digit:] and
// the rest -- is a set of single characters, so it expands to an ordinary
// character class and needs nothing else. A word dictionary is a list of
// strings, one per member: '[:bip39en:]{24}' is a set of BIP-39 passphrases
// drawn from the two thousand words of that list. Those cannot be a character
// class, since a member is more than a character, so they become a node kind
// of their own; see the is_dict handling across the library.
//
// The library does no file I/O -- it must run in a browser, where there is no
// filesystem -- so it does not itself know where a dictionary comes from. A
// caller registers one by name, or installs a resolver that is asked whenever
// an unknown name is parsed. rxenum's resolver reads name.dict off disk; the
// browser build registers its built-ins and whatever the user has uploaded.

#include <string.h>
#include "rxe.h"
#include "dict.h"

/* -------------------------- The POSIX classes --------------------------- */

// Each entry is the body of the bracket expression it stands for, without the
// closing ']'. Ranges and \x escapes are read by handle_character_class, so
// these say exactly what the class contains and nothing has to enumerate a
// character at a time here.

static const struct { const char *name, *body; } posix[] = {
    { "alpha",  "A-Za-z" },
    { "digit",  "0-9" },
    { "alnum",  "0-9A-Za-z" },
    { "upper",  "A-Z" },
    { "lower",  "a-z" },
    { "xdigit", "0-9A-Fa-f" },
    { "word",   "0-9A-Za-z_" },
    { "space",  "\\x9-\\xd " },        // tab, newline, vtab, formfeed, cr, space
    { "blank",  "\\x9 " },             // tab and space
    { "punct",  "!-/:-@[-`{-~" },      // the ASCII punctuation runs
    { "cntrl",  "\\x0-\\x1f\\x7f" },
    { "graph",  "\\x21-\\x7e" },       // visible characters
    { "print",  "\\x20-\\x7e" },       // graph plus the space
    { NULL, NULL }
};

const char *rxe_posix_class(const char *name, int len)
{
    int i;
    for (i=0;posix[i].name;i++)
        if ((int)strlen(posix[i].name)==len && !memcmp(posix[i].name,name,len))
            return posix[i].body;
    return NULL;
}

/* ------------------------ The word dictionaries ------------------------- */

struct dict {
    char        *name;
    char       **words;
    int          nwords;
    struct dict *next;
};

static struct dict *dicts;                 // the registry, a plain list
static int (*resolver)(const char *name);  // asked on a miss, may register

static struct dict *find(const char *name, int len)
{
    struct dict *d;
    for ( d = dicts ; d ; d = d->next )
        if ((int)strlen(d->name)==len && !memcmp(d->name,name,len)) return d;
    return NULL;
}

int rxe_register_dict(const char *name, const char **words, int nwords)
{
    int i;
    struct dict *d = find(name,(int)strlen(name));
    if (d) {
        // Re-registering a name replaces it. Release the old contents first.
        for (i=0;i<d->nwords;i++) rxe_mem_free(d->words[i]);
        if (d->words) rxe_mem_free(d->words);
    } else {
        d = NEW(1,struct dict);
        d->name = NEW((int)strlen(name)+1,char);
        strcpy(d->name,name);
        d->next = dicts;
        dicts = d;
    }
    d->nwords = nwords;
    d->words = nwords ? NEW(nwords,char *) : NULL;
    for (i=0;i<nwords;i++) {
        int wl = (int)strlen(words[i]);
        d->words[i] = NEW(wl+1,char);
        memcpy(d->words[i],words[i],wl+1);
    }
    return 0;
}

void rxe_set_dict_resolver(int (*fn)(const char *name))
{
    resolver = fn;
}

int rxe_lookup_dict(const char *name, int len, char ***words, int *nwords)
{
    struct dict *d = find(name,len);
    if (!d && resolver) {
        // The resolver is handed a NUL-terminated name, which the parser's
        // pointer into the pattern is not, so make a temporary copy of it.
        char stackbuf[64], *heap = NULL, *nul = stackbuf;
        if (len >= (int)sizeof(stackbuf)) nul = heap = NEW(len+1,char);
        memcpy(nul,name,len);
        nul[len] = 0;
        if (resolver(nul)) d = find(name,len);
        if (heap) rxe_mem_free(heap);
    }
    if (!d) return 0;
    *words = d->words;
    *nwords = d->nwords;
    return 1;
}

void rxe_free_dicts(void)
{
    struct dict *d, *next;
    int i;
    for ( d = dicts ; d ; d = next ) {
        next = d->next;
        for (i=0;i<d->nwords;i++) rxe_mem_free(d->words[i]);
        if (d->words) rxe_mem_free(d->words);
        rxe_mem_free(d->name);
        rxe_mem_free(d);
    }
    dicts = NULL;
}
