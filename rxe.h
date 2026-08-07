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

// Parse options: the bitmask handed to rxe_parse(), and the same bits the
// inline (?...) groups set and clear.

#define RXE_CASELESS                 0x0001
#define RXE_DOTALL                   0x0002
#define RXE_LEFT_TO_RIGHT            0x0004

// Flags recorded on the parse tree itself, in struct rxe's 'flags' field.
// These used to be #defined in two separate .c files, out of sight of each
// other and of the options above. They are now here, and deliberately
// allocated from a range that does not overlap the parse options: the two
// sets live in different fields, so testing one against the other is a
// mistake that should not be able to look plausible.

#define RXE_FLAG_CLOSED_BRACKET      0x0100
#define RXE_FLAG_HAS_BKRTABLE        0x0200
#define RXE_FLAG_VARIABLE_REPEAT     0x0400
#define RXE_FLAG_LEFT_TO_RIGHT       0x0800

/* -------------------------- Global Declarations ------------------------- */

// Parse status codes paired with their messages, written down once. The enum
// below and the message table in parse.c are both generated from this list, so
// they cannot fall out of step. They previously could: the enum lived here and
// the table there, and rxe_error_message() indexes the table with a value of
// the enum. RXE_OK must stay first so that it is zero.

#define RXE_STATUS_LIST(X)                                                     \
    X(RXE_OK,                           "")                                    \
    X(RXE_INFINITE,                     "infinite")                            \
    X(RXE_TOO_MANY_PARENS,              "extraneous parentheses")              \
    X(RXE_TOO_LITTLE_PARENS,            "missing parentheses")                 \
    X(RXE_LONE_QUANTIFIER,              "nothing before quantifier")           \
    X(RXE_NESTED_QUANTIFIERS,           "nested quantifiers")                  \
    X(RXE_UNTERMINATED_LITERAL,         "unterminated literal")                \
    X(RXE_UNTERMINATED_CLASS,           "unterminated character class")        \
    X(RXE_UNTERMINATED_REPEAT,          "unterminated repetition")             \
    X(RXE_UNTERMINATED_FLAGS,           "unterminated flags")                  \
    X(RXE_BAD_REPETITION,               "bad repetition parameters")           \
    X(RXE_UNIMPLEMENTED,                "unimplemented")                       \
    X(RXE_INVALID_BACKREF,              "invalid backreference")               \
    X(RXE_INVALID_CONSTANT,                                                    \
      "stray non-digit characters in numeric constant")                        \
    X(RXE_UNTERMINATED_HEX_CONSTANT,    "unterminated hex constant")           \
    X(RXE_BACKREF_INTO_VARIABLE_REPEAT,                                        \
      "backreference into a variably repeated group")

enum rxe_parse_status {
#define RXE_STATUS_ENUM_ENTRY(name,msg) name,
    RXE_STATUS_LIST(RXE_STATUS_ENUM_ENTRY)
#undef RXE_STATUS_ENUM_ENTRY
    RXE_NSTATUS                 // Must be last; counts the entries above
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

struct rxe *rxe_parse(const char *str, int flags);
enum rxe_parse_status rxe_error(struct rxe *rxe);
const char *rxe_error_message(struct rxe *rxe);

char *rxe_current(char *str, int maxlen, struct rxe *rxe);
int rxe_iterate(struct rxe *rxe);
int rxe_seek(struct rxe *rxe, mpz_t pos);

void rxe_init(void);
struct rxe *rxe_new(void);
void rxe_node_deep_clone(struct rxe_alt *alt, struct rxe_node *src_node, int shallow);
struct rxe *rxe_deep_clone(struct rxe *src_rxe);
void rxe_free(struct rxe *rxe);

void *kmalloc(size_t size, const char *file, int line);

// A keyed permutation of the integer mapping, so a set can be walked in an
// order that depends on a key while every member is still visited exactly
// once. See permute.c. Pass an index in [0, domain) to rxe_permutation_map
// and seek to what comes back.

struct rxe_permutation;

struct rxe_permutation *rxe_permutation_new(const mpz_t domain, const char *key);
void rxe_permutation_free(struct rxe_permutation *perm);
void rxe_permutation_map(mpz_t result, struct rxe_permutation *perm,
                         const mpz_t index);

/* ------------------------ Macro-Defined Functions ----------------------- */

#define NEW(n,type) ((type *)kmalloc(sizeof(type)*(n),__FILE__,__LINE__))

#define rxe_next(rxe) (!rxe_iterate(rxe))

/* ------------------------ Macro-Defined Functions ----------------------- */

#endif // __RXE_H__

