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

#ifndef __RXE_H__
#define __RXE_H__

#include <gmp.h>
#include <stdlib.h>

#define RXE_VERSION "1.0.0"

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

// The rep_max of a repetition with no upper bound, as in 'a*', 'a+' or
// 'a{3,}'. Such a repetition is infinite unless the thing it repeats matches
// nothing at all, in which case only the empty run exists.

#define RXE_REP_UNBOUNDED            (-1)

// Materializing one member of a set costs memory in proportion to its length:
// the string itself, and -- for a repetition -- one index per position. A set
// can be indexed and counted without ever paying that, but rendering a single
// member that runs to gigabytes will exhaust the host. rxe_max_member caps the
// bytes a rendered member may occupy; a member that would exceed it is refused
// with RXE_TOO_BIG rather than allocated. Zero lifts the cap entirely. This is
// a limit on a single line of output, never on how many members the set has:
// the cardinality stays unbounded, and seeking still reaches every index.
#define RXE_DEFAULT_MAX_MEMBER       (1u<<20)   // one mebibyte

// A hard ceiling on a fixed repetition count, well above any real use, that
// keeps '{n}' from overflowing the int it is parsed into (and from demanding a
// cardinality integer the size of a disk). Distinct from the soft byte cap
// above: this one bounds the count, not the rendered size.
#define RXE_MAX_REPEAT               (100*1000*1000)

#define RXE_FLAG_CLOSED_BRACKET      0x0100
#define RXE_FLAG_HAS_BKRTABLE        0x0200
#define RXE_FLAG_VARIABLE_REPEAT     0x0400
#define RXE_FLAG_LEFT_TO_RIGHT       0x0800
#define RXE_FLAG_SHORTLEX            0x1000

/* -------------------------- Global Declarations ------------------------- */

// Parse status codes paired with their messages, written down once. The enum
// below and the message table in parse.c are both generated from this list, so
// they cannot fall out of step. They previously could: the enum lived here and
// the table there, and rxe_error_message() indexes the table with a value of
// the enum. RXE_OK must stay first so that it is zero.

#define RXE_STATUS_LIST(X)                                                     \
    X(RXE_OK,                           "")                                    \
    X(RXE_INFINITE,                     "infinite")                            \
    X(RXE_RECURSIVE_BACKREF,                                                   \
      "backreference to the group it is inside")                               \
    X(RXE_NESTED_UNBOUNDED,                                                    \
      "unbounded repetition of a possibly empty expression")                   \
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
      "backreference into a variably repeated group")                          \
    X(RXE_UNTERMINATED_DICT,            "unterminated dictionary")             \
    X(RXE_UNKNOWN_DICT,                 "unknown dictionary")                  \
    X(RXE_BAD_CHOOSE,                   "bad combinatorial parameters")        \
    X(RXE_CHOOSE_INFINITE,              "combinatorial choice over an infinite set") \
    X(RXE_BAD_SHUFFLE,                  "unterminated shuffle key")            \
    X(RXE_SHUFFLE_INFINITE,             "shuffle key over an infinite set")    \
    X(RXE_TOO_BIG,                      "member too large to materialize")

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

// How many members an expression has of each length, rather than in total.
//
// A cardinality is enough to walk a finite set, because place value can order
// it. It is not enough to walk an infinite one in a useful order: the members
// have to come out shortest first, and that means being able to ask how many
// there are of each length rather than how many there are altogether.
//
// count[L] is how many members have length exactly L, and is meaningful for L
// up to 'max'. Nothing is computed until it is asked for, and then only as far
// as it was asked, which is what keeps this affordable: enumerating the first
// few thousand members of '[a-z]{1,20000}a*' asks about lengths up to a dozen
// or so and never touches the twenty thousand.

struct rxe_lens {
    int    max;                   // counts known for lengths 0..max, -1 if none
    int    alloc;                 // entries allocated in count
    mpz_t *count;                 // count[L] members of length exactly L
};

// An alternation node, arranged as a doubly linked list with head and tail
// anchors in 'struct rxe'.

struct rxe_alt {
    int nnodes;                   // Number of nodes in this alternation
    int ninf;                     // How many of its nodes are infinite
    struct rxe_lens lens;         // Members by length, over all its nodes
    mpz_t nitems;                 // Number of items, counting finite nodes only
    mpz_t start;                  // Start point in the integer mapping
    struct rxe_node *curr;        // Current node being iterated
    struct rxe_node *head;        // Start of the linked list of nodes
    struct rxe_node *tail;        // End of the linked list of nodes
    struct rxe_alt  *prev;        // Pointer to the next alternation
    struct rxe_alt  *next;        // Pointer to the previous alternation
    struct rxe      *owner;       // The expression this belongs to
};

// A single node, representing a character class, a subexpression, a
// backreference or a repetition. The characters comprising the class are in a
// dynamically allocated string pointed to by 'str'. This string is not
// null-terminated; instead, the number of characters it holds is in 'len'.
// The routines must be prepared for the possibility that 'str' might be NULL.
// A subexpression or backreference is pointed to by the 'rxe' field. If it is
// a backref, the flag is_backref shall be true. Nodes are arranged as a
// doubly linked list with head and tail anchors in 'struct rxe_alt'.
//
// A repetition node has is_repeat set. It holds a single copy of the repeated
// subexpression in 'rxe' and repeats it between rep_min and rep_max times,
// which is why 'rxe' alone cannot give the node's cardinality: for every other
// kind of node the two coincide, but here the node's own nitems is the sum of
// a geometric series over the subexpression's. Its state is the repeat count
// currently selected and one index per position, rather than one materialised
// copy of the subexpression per position: repeating a subexpression of
// cardinality b between 0 and m times has m+1 alternations holding m(m+1)/2
// copies between them, so writing them out cost quadratic memory and put a
// ceiling of a few thousand on m. See repeat.c.

struct rxe_node {
    int   len;                    // Number of chars in *str
    char *str;                    // string with possible characters
    mpz_t nitems;                 // No of items in this set and its subsets
    int   iterator;               // Current item being iterated
    int   is_backref;             // True if this node is a backreference
    int   is_repeat;              // True if this node is a repetition
    int   is_comb;                // True if this is a combination/permutation
    int   comb_perm;              // When is_comb: 1 ordered (perm), 0 unordered
    mpz_t comb_index;             // When is_comb or is_shuffle: current index
    int   is_shuffle;             // True if this group carries a shuffle key
    struct rxe_permutation *shuffle; // The keyed permutation, when is_shuffle
    int   is_dict;                // True if this node draws from a dictionary
    int   nwords;                 // Number of words, when is_dict
    char **words;                 // The words, borrowed from the registry
    int   is_inf;                 // True if this node has no largest member
    int   rep_min;                // Fewest repetitions, when is_repeat
    int   rep_max;                // Most repetitions, or RXE_REP_UNBOUNDED
    int   rep_count;              // Repetitions currently selected
    int   rep_alloc;              // How many rep_digit entries are live
    mpz_t *rep_digit;             // One index into rxe per position
    int   *rep_len;               // That position's length, in length order
    struct rxe_lens lens;         // Members of this node by length
    struct rxe_lens rest;         // ...of every node less significant than it
    struct rxe *rxe;              // Pointer to a subexpression or backref
    struct rxe *refers_to;        // For a (?N) subroutine: the group it copies,
                                  // so a drawing can collapse the copy to a link
    int   src_start;              // This node's span in the root's source text,
    int   src_end;                // as byte offsets [start,end); 0,0 if unknown
    struct rxe_node *prev;        // Pointer to the next node
    struct rxe_node *next;        // Pointer to the previous node
    struct rxe_alt  *owner;       // The alternation this belongs to
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
    int ninf;                      // how many of them have no largest member
    enum rxe_parse_status status;  // error code returned during parsing
    int error_pos;                 // offset into source of a parse error, only
                                  // meaningful when status is not RXE_OK
    struct rxe_alt *head;          // start of the linked list of alternations
    struct rxe_alt *tail;          // end of the linked list of alternations
    struct rxe_alt *curr;          // current item being iterated
    mpz_t nitems;                  // items in the set, finite alternations only
    mpz_t index;                   // index the expression currently sits at
    struct rxe_lens lens;          // Members by length, over all its alternations
    struct rxe_backref_table *brt; // backreferences table (only on root node)
    int flags;                     // miscellaneous flags
    char *source;                  // a private copy of the input text, on the
                                  // root only, that node spans point into
};

extern void *(*rxe_mem_alloc)(size_t);
extern void (*rxe_mem_free)(void *);

// The cap on a rendered member's length in bytes; see RXE_DEFAULT_MAX_MEMBER.
// A front-end sets it to suit where its output goes -- a page's DOM tolerates
// far less than a file does. Zero means no cap.
extern size_t rxe_max_member;
void rxe_set_max_member(size_t bytes);

// Raised whenever a render is refused or truncated for exceeding rxe_max_member.
// A front-end resets it before rendering and reads it after to tell a genuine
// member from a stub. rxe_check_overflow reads and clears it in one step.
extern int rxe_member_overflow;
int rxe_check_overflow(void);


/* -------------------------- Function Prototypes ------------------------- */

struct rxe *rxe_parse(const char *str, int flags);
enum rxe_parse_status rxe_error(struct rxe *rxe);
const char *rxe_error_message(struct rxe *rxe);

// Where in the input a parse error was found, as a byte offset. Only meaningful
// when rxe_error() is not RXE_OK; a front-end can point a caret at it.
int rxe_error_pos(struct rxe *rxe);

// Non-zero when the expression describes an infinite set. rxe->nitems then
// counts only the part of it that is finite, and is not the size of the set;
// there is no largest index, and rxe_seek accepts any.

int rxe_is_infinite(struct rxe *rxe);

// Non-zero when the expression is enumerated shortest member first. True of
// every infinite expression whose lengths can be counted; a backreference
// ties two positions' lengths together and defeats that, and such an
// expression falls back to the diagonal order instead. Finite expressions are
// enumerated by place value as they always were and report zero.

int rxe_is_shortlex(struct rxe *rxe);

char *rxe_current(char *str, int maxlen, struct rxe *rxe);
int rxe_iterate(struct rxe *rxe);
int rxe_seek(struct rxe *rxe, mpz_t pos);

// rank -- the inverse of seek. Given a string, find where it sits in the set.
// A member can appear at more than one index (a set may hold duplicates), so
// rank is many-valued: rxe_rank returns the smallest index the string reaches,
// rxe_rank_count how many it reaches (a count above one proves a duplicate),
// and rxe_rank_all visits each in turn. The string must equal a member whole.
//
// rxe_rank returns 0 and sets out when the string is a member, 1 when it is
// not, and -1 when the set is one rank cannot yet handle -- an infinite set, a
// {{k}} choice, a (?~key:) shuffle, a backreference, or left-to-right order --
// in which case rxe_rank_reason() names why. rxe_rank_count returns 0 on
// success or -1 on refusal. rxe_rank_all returns how many indices it emitted,
// or -1 on refusal; its callback returns non-zero to stop early, which is how
// a caller caps a listing that count told it would be huge.
typedef int (*rxe_rank_cb)(const mpz_t index, void *ctx);
int  rxe_rank(struct rxe *rxe, const char *s, mpz_t out);
int  rxe_rank_count(struct rxe *rxe, const char *s, mpz_t out);
long rxe_rank_all(struct rxe *rxe, const char *s, rxe_rank_cb cb, void *ctx);
const char *rxe_rank_reason(void);

void rxe_init(void);
struct rxe *rxe_new(void);
void rxe_node_deep_clone(struct rxe_alt *alt, struct rxe_node *src_node);
struct rxe *rxe_deep_clone(struct rxe *src_rxe);
void rxe_free(struct rxe *rxe);

void *kmalloc(size_t size, const char *file, int line);

// Named dictionaries, written [:name:] in a pattern. A word dictionary is a
// list of strings, one per member, so '[:bip39en:]{24}' enumerates the
// passphrases drawn from that word list. POSIX classes -- [:alpha:] and the
// rest -- are recognised too, as ordinary single-character classes.
//
// The library does no file I/O, so a caller supplies the words: register one
// by name outright, or install a resolver called the first time an unknown
// name is seen, which may load and register it and return non-zero. rxenum's
// resolver reads name.dict; a browser build registers its own.
int  rxe_register_dict(const char *name, const char **words, int nwords);
void rxe_set_dict_resolver(int (*resolver)(const char *name));
void rxe_free_dicts(void);

// A keyed permutation of the integer mapping, so a set can be walked in an
// order that depends on a key while every member is still visited exactly
// once. See permute.c. Pass an index in [0, domain) to rxe_permutation_map
// and seek to what comes back.

struct rxe_permutation;

struct rxe_permutation *rxe_permutation_new(const mpz_t domain, const char *key);
void rxe_permutation_free(struct rxe_permutation *perm);
struct rxe_permutation *rxe_permutation_clone(const struct rxe_permutation *perm);

// A per-subexpression shuffle, written '(?~key:re)': the group's own index is
// passed through a keyed permutation before it is seeked into, so its members
// come out reordered by the key while every other position is untouched. Built
// on the same permutation the whole-set '-k' uses, over the group's own
// cardinality. See permute.c.
void rxe_shuffle_make(struct rxe_node *node, const char *key, int keylen);
int  rxe_shuffle_seek(struct rxe_node *node, const mpz_t pos);
int  rxe_shuffle_iterate(struct rxe_node *node);
void rxe_shuffle_free(struct rxe_node *node);

void rxe_permutation_map(mpz_t result, struct rxe_permutation *perm,
                         const mpz_t index);

/* ------------------------ Macro-Defined Functions ----------------------- */

#define NEW(n,type) ((type *)kmalloc(sizeof(type)*(n),__FILE__,__LINE__))

#define rxe_next(rxe) (!rxe_iterate(rxe))

/* ------------------------ Macro-Defined Functions ----------------------- */

#endif // __RXE_H__

