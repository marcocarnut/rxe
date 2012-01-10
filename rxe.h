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

#ifndef __RXE_H__
#define __RXE_H__

#include <gmp.h>
#include <stdlib.h>

/* ------------------------ Macro-Defined Constants ----------------------- */

#define RXE_CASELESS                 1
#define RXE_DOTALL                   2

/* -------------------------- Global Declarations ------------------------- */

enum rxe_parse_status {
    RXE_OK = 0,                 // Must be zero
    RXE_INFINITE,
    RXE_TOO_MANY_PARENS,
    RXE_TOO_LITTLE_PARENS,
    RXE_LONE_QUANTIFIER,
    RXE_NESTED_QUANTIFIERS,
    RXE_UNTERMINATED_LITERAL,
    RXE_UNTERMINATED_CLASS,
    RXE_UNTERMINATED_REPEAT,
    RXE_UNTERMINATED_FLAGS,
    RXE_BAD_REPETITION,
    RXE_UNIMPLEMENTED,
    RXE_INVALID_BACKREF,
    RXE_INVALID_CONSTANT,
    RXE_UNTERMINATED_HEX_CONSTANT,
};

// ---- Main data structures

// Picture a regex like:  a | [bcd]e | ( f | g ) |
// The full regexe is a 'struct rxe' with 4  alternations ('struct rxe_alt') in
// a doubly linked. The first alternation has a linked list with only one
// node ('struct rxe_node') containing the "a" in its string. The second
// alternation has two nodes: one containing the string 'bcd' and the other
// containing the string 'e'. Those strings are in 'str' and they are not
// zero-terminated; instead, their lenghts is specified in 'len'. The third
// alternation has a single node with no string but that points (via its
// member 'rxe') to another subexpression contaning one alternation and
// two nodes 'f' ang 'g'. The final alternation is empty.

struct rxe;         // forward definitions needed due to the recursive...
struct rxe_node;    // ...nature of the data structures

// An alternation node, arranged as a doubly linked list with head and tail
// anchors in 'struct rxe'.

struct rxe_alt {
    int nnodes;                   // Number of nodes in this alternation
    mpz_t nitems;                 // Total number of items in the set
    mpz_t start;                  // Start point in the integer mapping
    struct rxe_node *curr;        // Current node being iterated
    struct rxe_node *head;        // Start of the linked list of nodes
    struct rxe_node *tail;        // End of the linked list of nodes
    struct rxe_alt  *prev;        // Pointer to the next alternation
    struct rxe_alt  *next;        // Pointer to the previous alternation
};

// A single node, representing a character class, a subexpression or a
// backreference. The characters comprising the class are in a dynamically
// allocated string pointed to by 'str'. This string is not null-terminated;
// instead, the number of characters it holds is in 'len'. The routines must
// be prepared for the possibility that 'str' might be NULL. A subexpression
// or backreference is pointed to by the 'rxe' field. If it is a backref, the
// flag back is_backref shall be true. Nodes are arranged as a doubly linked
// list with head and tail anchors in 'struct rxe_alt'.

struct rxe_node {
    int   len;                    // Number of chars in *str
    char *str;                    // string with possible characters
    mpz_t nitems;                 // No of items in this set and its subsets
    mpz_t start;                  // Start point in the integer mapping
    int   iterator;               // Current item being iterated
    int   is_backref;             // True if this node is a backreference
    struct rxe *rxe;              // Pointer to a subexpression or backref
    struct rxe_node *prev;        // Pointer to the next node
    struct rxe_node *next;        // Pointer to the previous node
};

// A backreference table. All subexpressions point to it, but only the root
// "owns" it in the sense of being responsible for its deallocation.

struct rxe_backref_table {
    int nbackrefs;                 // qty of backrefs currently in table
    int maxbackrefs;               // max qty of backrefs the array can hold
    struct rxe **bkref;            // the backreference table itself
};

// Structure to represent a fully parsed (sub)regex as a linked list of
// alternations.

struct rxe {
    int nalts;                     // number of alternations in the linked list
    enum rxe_parse_status status;  // error code returned during parsing
    struct rxe_alt *head;          // start of the linked list of alternations
    struct rxe_alt *tail;          // end of the linked list of alternations
    struct rxe_alt *curr;          // current item being iterated
    mpz_t nitems;                  // number of items in the set
    struct rxe_backref_table *brt; // backreferences table (only on root node)
    int flags;                     // miscellaneous flags
};

extern void *(*rxe_mem_alloc)(size_t);
extern void (*rxe_mem_free)(void *);


/* -------------------------- Function Prototypes ------------------------- */

struct rxe *rxe_parse(char *str, int flags);
enum rxe_parse_status rxe_error(struct rxe *rxe);
char *rxe_error_message(struct rxe *rxe);

char *rxe_current(char *str, int maxlen, struct rxe *rxe);
int rxe_iterate(struct rxe *rxe);
int rxe_seek(struct rxe *rxe, mpz_t pos);

void rxe_init(void);
struct rxe *rxe_new(void);
void rxe_node_deep_clone(struct rxe_alt *alt, struct rxe_node *src_node, int shallow);
struct rxe *rxe_deep_clone(struct rxe *src_rxe);
void rxe_free(struct rxe *rxe);

void *kmalloc(size_t size, char *file, int line);

/* ------------------------ Macro-Defined Functions ----------------------- */

#define NEW(n,type) ((type *)kmalloc(sizeof(type)*(n),__FILE__,__LINE__))

#define rxe_next(rxe) (!rxe_iterate(rxe))

/* ------------------------ Macro-Defined Functions ----------------------- */

#endif // __RXE_H__

