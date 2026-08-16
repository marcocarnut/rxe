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

#include "rxe.h"
#include "rxe_alt.h"
#include "repeat.h"
#include "comb.h"
#include "lens.h"
#include "dict.h"
#include "rxe_node.h"
#include "bkreftbl.h"
#include <string.h>
#include <stdio.h> 

/* ------------------------ Macro-Defined Constants ----------------------- */

#define FLAG_SET                     1
#define FLAG_RESET                   0

/* -------------------------- Global Declarations ------------------------- */

// Status/error message strings

const char *rxe_status_msgs[] = {
#define RXE_STATUS_MSG_ENTRY(name,msg) msg,
    RXE_STATUS_LIST(RXE_STATUS_MSG_ENTRY)
#undef RXE_STATUS_MSG_ENTRY
};

// Both this table and the enum come from RXE_STATUS_LIST in rxe.h, so they
// cannot disagree. The assert stays as a tripwire in case someone later
// expands one of them by hand.

_Static_assert(
    sizeof(rxe_status_msgs)/sizeof(rxe_status_msgs[0]) == RXE_NSTATUS,
    "rxe_status_msgs[] is out of sync with enum rxe_parse_status"
);

// Backslash-letter escape table.
// Empty string means ignored, NULL means unimplemented, anything else is
// a character or character class to be used instead.
// Some escapes, like \x and \g, are hardcoded and handled before this table
// is looked up.

const char *backslash_letters[] = {
    "",                // \A: beginning of the string assertion, ignored
    "",                // \B: match at non word assertion, ignored
    NULL,              // \C: C language octet, unimplemented
    "^0-9]",           // \D: Non-digit character
    NULL,              // \E: End \Q quoting, unimplemented
    "F",               // \F: unused, gives 'F' char itself
    "G",               // \G: unused, gives 'G' char itself
    "H",               // \H: unused, gives 'H' char itself
    "I",               // \I: unused, gives 'I' char itself
    "J",               // \J: unused, gives 'J' char itself
    "",                // \K: keep, ignored
    "L",               // \L: unused, gives 'L' char itself
    "M",               // \M: unused, gives 'M' char itself
    "^\n]",            // \N: any but \n
    "O",               // \O: unused, gives 'O' char itself
    "",                // \P: negative unicode property, unimplemented
    "Q",               // \Q: unused, gives 'Q' char itself
    "R",               // \R: unused, gives 'R' char itself
    "^ \t]",           // \S: non-whitespace
    "T",               // \T: unused, gives 'T' char itself
    "U",               // \U: unused, gives 'U' char itself
    "V",               // \V: unused, gives 'V' char itself
    "^a-zA-Z0-9_]",    // \W: non-word character
    "X",               // \X: unused, gives 'X' char itself
    "Y",               // \Y: unused, gives 'Y' char itself
    "Z",               // \Z: unused, gives 'Z' char itself
    "[",               // \[: unused, gives '[' char itself
    "\\",              // \\: unused, gives '\' char itself
    "]",               // \]: unused, gives ']' char itself
    "^",               // \^: unused, gives '^' char itself
    "_",               // \_: unused, gives '_' char itself
    "`",               // \`: unused, gives '`' char itself
    "\x7",             // \a: alarm bell
    "",                // \b: word boundary, ignored
    NULL,              // \c: control character (special cased)
    "0-9]",            // \d: digit
    "\x1b",            // \e: escape character
    "\x0c",            // \f: form feed
    NULL,              // \g: backreference, unimplemented
    "h",               // \h: unused, gives the 'h' char itself
    "i",               // \i: unused, gives the 'i' char itself
    "j",               // \j: unused, gives the 'j' char itself
    NULL,              // \k: named backreference, unimplemented
    NULL,              // \l: lowercase next char, unimplemented
    NULL,              // \m: named backreference, unimplemented
    "\n",              // \n: newline character
    NULL,              // \o: octal, unimplemented
    NULL,              // \p: unicode property, unimplemented
    "q",               // \q: unused, gives the 'q' char itself
    "\r",              // \r: return character
    " \t]",            // \s: space character class
    "\t",              // \t: horizontal tabulation
    NULL,              // \u: uppercase next char, unimplemented
    "v",               // \v: unused, gives the 'v' char itself
    "a-zA-Z0-9_]",     // \w: word character,
    NULL,              // \x: hexadecimal, unimplemented
    "y",               // \y: unused, 'y' character itself
    "z"                // \z: unused, 'z' character itself
};

/* -------------------------- Function Prototypes ------------------------- */

const char *parse(struct rxe *rxe, mpz_t ret, const char *str, int flags,
                  int depth, const char *base);
const char *handle_repeats(struct rxe_alt *alt, const char *str,
                           int flags, enum rxe_parse_status *status);
int build_repeat(struct rxe_node *node, int r0, int r1, int flags,
                 enum rxe_parse_status *status);
static const char *parse_choose_params(const char *str, int *lo, int *hi,
                                       int *perm, int *star, int *chop,
                                       enum rxe_parse_status *status);
static int build_choose(struct rxe_node *node, int lo, int hi, int perm,
                        int star, int chop, int flags, enum rxe_parse_status *status);
const char *handle_character_class(struct rxe *rxe, struct rxe_alt *alt, mpz_t ret, const char *str, int flags);
const char *handle_dictionary(struct rxe *rxe, struct rxe_alt *alt, mpz_t ret, const char *str, int flags);
const char *handle_flags(const char *str, int *flags);
const char *handle_recursion(const char *str, mpz_t n, struct rxe_alt *alt, struct rxe *rxe);
const char *handle_backreferences(const char *str, mpz_t n, struct rxe_alt *alt, struct rxe *rxe);
const char *handle_hex_char(struct rxe *rxe, const char *str, char *chr);

/* ------------------------------------------------------------------------ */

enum rxe_parse_status rxe_error(struct rxe *rxe)
{
    return rxe->status;
}

const char *rxe_error_message(struct rxe *rxe)
{
    // Indexing the table with an out-of-range status is what turned the
    // uninitialised rxe->status into a segfault. Cheap to rule out for good.
    if (!rxe || (unsigned)rxe->status >= (unsigned)RXE_NSTATUS)
        return "unknown error";
    return rxe_status_msgs[rxe->status];
}

int rxe_error_pos(struct rxe *rxe)
{
    return rxe ? rxe->error_pos : 0;
}

// This is the main parser routine. It calls itself recursively to handle
// subexpressions. 'rxe' is a previously created struct rxe store the parse 
// tree, 'ret' is a arbitrary precision integer with the number of items in
// the set, 'str' points to the start of the string being parsed, 'flags' is
// a bitmask of RXE_FLAG constants, depth is the depth of the recursive call,
// zero being the first.
//
// On success, returns a pointer to the character after the successfully
// parsed (sub)expression. On error, the return value is undefined.

// parse() leaves through eighteen separate points, most of them error paths.
// Route every one of them through here so that none can forget to release the
// accumulators.

static const char *parse_done(mpz_t x, mpz_t n, mpz_t p, const char *str)
{
    mpz_clear(x);
    mpz_clear(n);
    mpz_clear(p);
    return str;
}

const char *parse(struct rxe *rxe, mpz_t ret, const char *str, int flags,
                  int depth, const char *base)
{
    mpz_t x,n,p;
    mpz_init_set_ui(x,1);  // Multiplicative accumulator
    mpz_init_set_ui(n,1);  // Current number of elements
    mpz_init_set_ui(p,1);  // Previous n
    char c;
    int i, newflags, is_flag_group, quantifier = 0;
    const char *shuffle_key; int shuffle_key_len = 0;
    struct rxe_alt *alt = rxe_new_alt(rxe); 
    mpz_set(alt->start,ret);
    // Direction is decided while parsing but consulted while enumerating, so
    // unlike the other options it cannot just live in 'flags'; it has to be
    // recorded on the subexpression itself. Inheriting it here is what makes
    // (?L) apply to nested groups and (?-L:...) able to override it again.
    if (flags & RXE_LEFT_TO_RIGHT) rxe->flags |= RXE_FLAG_LEFT_TO_RIGHT;
    struct rxe_node *node;
    const char *str2;
    char prev=0;
    for (;;) {
        // Where this token begins in the source, and the tail before it, so the
        // node it produces can be given its span once, uniformly, below.
        const char *tok = str;
        struct rxe_node *tail0 = alt->tail;
        int quant_here = 0;
        // Track where we are, so a failure this iteration lands the error on
        // the token that caused it. Overwritten each turn; read only on error.
        rxe->error_pos = (int)(tok - base);
        switch (c = *str++) {
            // ---------------- Termination conditions ---------------
            // End of subexpression
            case ')': if (!depth) {
                          rxe->status = RXE_TOO_MANY_PARENS;
                          return parse_done(x,n,p,str);
                      }
                      // fall-thru
            // End of string
            case  0 : if (depth && !c) { 
                          rxe->status = RXE_TOO_LITTLE_PARENS;
                          return parse_done(x,n,p,str);
                      }
                      // fall-thru
            // Alternation: does not really finish; flushes partial
            // results, accumulates them and restarts
            case '|': mpz_mul(x,x,n);
                      // Count the endless positions now rather than tallying
                      // them as they appear. A quantifier can take one away
                      // again -- '(a*){0}' is just the empty string -- and a
                      // recount cannot fall out of step the way a running
                      // tally did.
                      alt->ninf = 0;
                      for ( node = alt->head ; node ; node = node->next )
                          if (node->is_inf) alt->ninf++;
                      // x is now this alternation's cardinality, counting the
                      // finite positions only. Record it: enumeration needs to
                      // tell an alternation that matches nothing (product
                      // zero) from one that matches only the empty string
                      // (product one, no nodes).
                      mpz_set(alt->nitems,x);
                      // A position that matches nothing empties the whole
                      // alternation, however endless the rest of it is.
                      if (!mpz_sgn(x)) alt->ninf = 0;
                      if (alt->ninf) {
                          // It has no size to add to the total; it is a
                          // dimension of its own, indexed above every finite
                          // alternation rather than after this one.
                          rxe->ninf++;
                      } else {
                          mpz_add(ret,ret,x);
                      }
                      if (c != '|') return parse_done(x,n,p,str);
                      // Below runs for alternation only. These are already
                      // live, so re-initialising them would orphan the limbs
                      // they hold; just assign.
                      mpz_set_ui(x,1);
                      mpz_set_ui(n,1);
                      mpz_set_ui(p,1);
                      alt = rxe_new_alt(rxe);
                      mpz_set(alt->start,ret);
                      break;
            // ------------------- Sub-expressions -----------------
            case '(': newflags = flags;
                      shuffle_key = NULL;
                      // '(?~key:re)' is the per-subexpression shuffle: the group
                      // is non-capturing and carries a key whose permutation
                      // reorders its members. The key runs to the first colon;
                      // everything else is an ordinary group.
                      if (str[0]=='?' && str[1]=='~') {
                          // The key runs to the first colon, but not across a
                          // parenthesis or the end -- those mean the colon is
                          // missing, not that the key contains them.
                          const char *ke = str+2;
                          while (*ke && *ke!=':' && *ke!='(' && *ke!=')') ke++;
                          if (*ke!=':') {
                              rxe->status = RXE_BAD_SHUFFLE;
                              return parse_done(x,n,p,str);
                          }
                          shuffle_key = str+2;
                          shuffle_key_len = (int)(ke-(str+2));
                          is_flag_group = 1;    // non-capturing, like (?:...)
                          str = ke+1;
                      } else {
                      // Only a group introduced by '?' can be one that merely
                      // sets flags. Without this test an empty group '()' also
                      // arrived at the branch below -- handle_flags returns
                      // straight away when there is no '?' -- and was
                      // discarded, so it captured nothing and consumed no
                      // backreference number. Perl makes it a capturing group
                      // that matches the empty string.
                      is_flag_group = (*str=='?');
                      str2 = handle_flags(str,&newflags);
                      if (!str2) {
                          rxe->status = RXE_UNTERMINATED_FLAGS;
                          return parse_done(x,n,p,str);
                      }
                      str = str2;
                      if (is_flag_group && *str==')') {
                          flags = newflags;
                          // A bare (?L) or (?-L) governs the whole enclosing
                          // group rather than just the rest of it. An odometer
                          // is a single unit: there is no coherent way for the
                          // direction to change partway along one.
                          if (flags & RXE_LEFT_TO_RIGHT)
                              rxe->flags |=  RXE_FLAG_LEFT_TO_RIGHT;
                          else
                              rxe->flags &= ~RXE_FLAG_LEFT_TO_RIGHT;
                          str++;
                          continue;
                      }
                      if (*str>='0' && *str<='9' && str[-1]=='?') {
                          str2 = handle_recursion(str,n,alt,rxe);
                          if (!str2) return parse_done(x,n,p,str);
                          str = str2;
                          quantifier = 0;
                          break;
                      }
                      if (*str==':') str++;
                      }   // end else (ordinary group)
                      mpz_set_ui(n,0);
                      struct rxe *sub_rxe = rxe_new();
                      node = rxe_new_node(alt);
                      sub_rxe->brt = rxe->brt;
                      // Every group introduced by '?' -- (?:...) and (?i:...)
                      // alike -- is non-capturing, so it must not take a
                      // backreference number. Registering them shifted every
                      // later \N by one: '(?:a)(b)\1' gave "aba" for what Perl
                      // reads as "abb", and '(?:a)(b)\2' was accepted at all.
                      if (!is_flag_group)
                          rxe_backref_table_add(rxe->brt,sub_rxe);
                      str = parse(sub_rxe,n,str,newflags,depth+1,base);
                      node->rxe = sub_rxe;
                      mpz_set(node->rxe->nitems,n);
                      mpz_set(node->nitems,n);
                      // However many endless dimensions the group holds
                      // inside, it is one of them from out here: a single
                      // index addresses the whole of it. It contributes a
                      // dimension rather than a factor, so it must leave the
                      // running product alone -- its finite total is zero
                      // when it has no finite alternation, and multiplying
                      // that in emptied the whole expression.
                      node->is_inf = rxe_is_infinite(sub_rxe);
                      if (node->is_inf) mpz_set_ui(n,1);
                      sub_rxe->flags |= RXE_FLAG_CLOSED_BRACKET;
                      if (sub_rxe->status) {
                          rxe->status = sub_rxe->status;
                          // The sub-parse ran over the same source, so its error
                          // offset is already in this expression's terms.
                          rxe->error_pos = sub_rxe->error_pos;
                          return parse_done(x,n,p,str);
                      }
                      // Attach the shuffle now that the group's cardinality is
                      // known. It reorders a finite set; an infinite one has no
                      // finite domain to permute over.
                      if (shuffle_key) {
                          if (node->is_inf) {
                              rxe->status = RXE_SHUFFLE_INFINITE;
                              return parse_done(x,n,p,str);
                          }
                          rxe_shuffle_make(node,shuffle_key,shuffle_key_len);
                      }
                      // A group is an element like any other, so a quantifier
                      // after it is its own and not a second one stacked on
                      // whatever came before. Without this, every construct of
                      // the form 'a+(b)*' was refused as nested quantifiers --
                      // '[a-z]+(-[a-z]+)*', a hyphenated word, among them --
                      // while Perl reads them all without complaint.
                      quantifier = 0;
                      break;
            // ---------------- Universal quantifiers --------------
            // 'a*' is 'a{0,}' and 'a+' is 'a{1,}'. They used to be a hard
            // error; an unbounded repetition is now a repetition like any
            // other whose upper bound happens not to exist.
            case '*':
            case '+': if (quantifier) {
                          rxe->status = RXE_NESTED_QUANTIFIERS;
                          return parse_done(x,n,p,str);
                      }
                      if (!alt->tail) {
                          rxe->status = RXE_LONE_QUANTIFIER;
                          return parse_done(x,n,p,str);
                      }
                      if (!build_repeat(alt->tail,c=='+',RXE_REP_UNBOUNDED,
                                        flags,&rxe->status))
                          return parse_done(x,n,p,str);
                      goto quantified;
            // ------------------- Quantifiers ---------------------
            case '?': if (quantifier) {
                          rxe->status = RXE_NESTED_QUANTIFIERS;
                          return parse_done(x,n,p,str);
                      }
                      if (!alt->tail) {
                          rxe->status = RXE_LONE_QUANTIFIER;
                          return parse_done(x,n,p,str);
                      }
                      // '?' is exactly {0,1}, and is now built by the same
                      // routine. It used to have its own copy of the
                      // construction, which is how the same bug -- first
                      // failing to clear the quantified node's own characters,
                      // then failing to inherit the enumeration direction --
                      // came to be fixed twice, separately.
                      if (!build_repeat(alt->tail,0,1,flags,&rxe->status))
                          return parse_done(x,n,p,str);
                      goto quantified;
            case '{': if (quantifier) {
                          rxe->status = RXE_NESTED_QUANTIFIERS;
                          return parse_done(x,n,p,str);
                      }
                      if (!alt->tail) {
                          rxe->status = RXE_LONE_QUANTIFIER;
                          return parse_done(x,n,p,str);
                      }
                      // '{{' is the nonstandard combinatorial quantifier: all
                      // combinations or permutations of the preceding set. A
                      // single '{' is an ordinary repetition. The status used
                      // to be smuggled back inside 'n', the mpz_t meant for the
                      // result, for want of anywhere else to put it. There is
                      // somewhere else now.
                      if (*str == '{') {
                          int c_lo,c_hi,c_perm,c_star,c_chop;
                          str2 = parse_choose_params(str+1,&c_lo,&c_hi,&c_perm,
                                                     &c_star,&c_chop,&rxe->status);
                          if (!str2) return parse_done(x,n,p,str);
                          if (!build_choose(alt->tail,c_lo,c_hi,c_perm,c_star,
                                            c_chop,flags,&rxe->status))
                              return parse_done(x,n,p,str);
                      } else {
                          str2 = handle_repeats(alt,str,flags,&rxe->status);
                          if (!str2) return parse_done(x,n,p,str);
                      }
                      str = str2;
                      // All three quantifiers land here. An endless one has no
                      // cardinality to fold into the product: it is a
                      // dimension of the alternation instead, counted in ninf.
            quantified: quant_here = 1;   // the tail's span grows to cover this
                        if (alt->tail->is_inf) {
                          mpz_set_ui(n,1);
                      } else {
                          mpz_set(n,alt->tail->nitems);
                      }
                      mpz_mul(x,x,n);
                      mpz_set_ui(n,1);   // already live; assign, do not re-init
                      mpz_set_ui(p,1);
                      quantifier = 1;
                      break;
            // ----------------- Character Classes -----------------
            case '[': if (*str==':') {
                          // '[:' introduces a dictionary, never a class whose
                          // first member is a colon. handle_dictionary sets
                          // the status itself, so a failure returns straight
                          // out rather than through the class error below.
                          str2 = handle_dictionary(rxe,alt,n,str,flags);
                          if (!str2) return parse_done(x,n,p,str);
                          str = str2;
                          quantifier = 0;
                          break;
                      }
                      str2 = handle_character_class(rxe,alt,n,str,flags);
                      if (!str2) {
                          rxe->status = RXE_UNTERMINATED_CLASS;
                          return parse_done(x,n,p,str);
                      }
                      str = str2;
                      quantifier = 0;
                      break;
            // ----------------- Wildcard Character ----------------
            case '.': handle_character_class(rxe,alt,n,
                          flags & RXE_DOTALL ? 
                              "\\x0-\\xFF]" : 
                              "\\x0-\\x9\\xB-\\xFF]",
                      0);
                      break;
            // ----------------- Escaped Characters ----------------
           case '\\': if (!*str) {
                          rxe->status = RXE_UNTERMINATED_LITERAL;
                          return parse_done(x,n,p,str);
                      }
                      c = *str; prev='\\';
                      quantifier = 0;
                      if (c>='0' && c<='9') {
                          str2 = handle_backreferences(str,n,alt,rxe);
                          if (!str2) return parse_done(x,n,p,str);
                          str = str2;
                          break;
                      }
                      str++;
                      // FIXME: Implement \o, \g with negative numeric
                      // references, \g with named references, \k, etc.
                      if (c == 'x') {
                          str2 = handle_hex_char(rxe,str,&c);
                          if (!str2) return parse_done(x,n,p,str);
                          str = str2;
                      }
                      else if (c>='A' && c<='z') {
                          // Named 'esc', not 'p': the outer accumulator is
                          // called p, and shadowing it here hid it from the
                          // cleanup call below.
                          const char *esc = backslash_letters[c-'A'];
                          if (esc) {
                              if ((c=esc[0])) {   // assign, then test
                                  if (esc[1]) {
                                      handle_character_class(rxe,alt,n,esc,0);
                                      break;
                                  } // else fall thru
                              } else {
                                  mpz_set_ui(n,1);
                                  break;
                              }
                          } else {
                             rxe->status = RXE_UNIMPLEMENTED;
                             return parse_done(x,n,p,str);
                          }
                      }
                      // fall thru
            case '$': if (!*str && prev!='\\') continue;
                      // fall-thru - a dollar anywhere else is a literal
             default: i = 1;
                      node = rxe_new_node(alt);
                      node->str = NEW(2,char);
                      node->str[0] = c;
                      if (flags & RXE_CASELESS) {
                          if ((c>='a' && c<='z') || (c>='A' && c<='Z')) {
                              i++;
                              node->str[1] = c ^ 0x20;
                          }
                      }
                      node->len = i;
                      mpz_set_ui(node->nitems,i);
                      mpz_set_ui(n,i);
                      quantifier = 0;
                      break;
        }
        mpz_mul(x,x,p);
        mpz_set(p,n);
        prev = c;
        // Record the span of whatever this iteration produced: a fresh atom
        // runs from its first character to here; a quantifier stretches the
        // tail it modified in place to take itself in.
        if (alt->tail) {
            if (alt->tail != tail0) {
                alt->tail->src_start = (int)(tok - base);
                alt->tail->src_end   = (int)(str - base);
            } else if (quant_here) {
                alt->tail->src_end   = (int)(str - base);
            }
        }
    }
}

const char *handle_hex_char(struct rxe *rxe, const char *str, char *chr)
{
    int val = 0;
    int done = 0;
    int demand_brace = 0;
    int ndigits = 0;
    if (*str=='{') {
        demand_brace = 1;
        str++;
    }
    while (!done) {
        char c = *str++;
        switch (c) {
            case 'a'...'f':
                c -= 32;
                // fall-thru
            case 'A'...'F':
                c -= 7;
                // fall-thru
            case '0'...'9':
                val = val * 16 + c-'0';
                if (++ndigits==2) done = 1;
                break;
            default:
                str--;
                // fall-thru
            case '}':
                done = 1;
                break;
        }
    }
    *chr = val&0xFF;
    if (demand_brace) {
        if (*str == '}') { 
            str++;
        } else {
            rxe->status = RXE_UNTERMINATED_HEX_CONSTANT;
            return NULL;
        }
    }
    return str;
}

const char *handle_backreferences(const char *str, mpz_t n, struct rxe_alt *alt, struct rxe *rxe)
{
    int brnum = 0;
    int done = 0;
    while (!done) {
        char c = *str++;
        switch (c) {
            case '0'...'9':
                brnum = brnum * 10 + c-'0';
                break;
            default:
                brnum--;
                str--;
                done = 1;
                break;
        }
    }
    struct rxe_node *node = rxe_new_node(alt);
    if (brnum<0 || brnum >= rxe->brt->nbackrefs) {
        rxe->status = RXE_INVALID_BACKREF;
        return NULL;
    }
    node->rxe = rxe->brt->bkref[brnum];
    if (!(node->rxe->flags & RXE_FLAG_CLOSED_BRACKET)) {
        // The group has not been closed yet, so this names the group it is
        // written inside. Nothing finite satisfies that.
        rxe->status = RXE_RECURSIVE_BACKREF;
        return NULL;
    }
    if (node->rxe->flags & RXE_FLAG_VARIABLE_REPEAT) {
        rxe->status = RXE_BACKREF_INTO_VARIABLE_REPEAT;
        return NULL;
    }
    node->is_backref = 1;
    mpz_set_ui(node->nitems,1);
    mpz_set_ui(n,1);
    return str;
}

const char *handle_recursion(const char *str, mpz_t n, struct rxe_alt *alt, struct rxe *rxe)
{
    int brnum = 0;
    int done = 0;
    while (!done) {
        char c = *str++;
        switch (c) {
            case  0: 
                rxe->status = RXE_TOO_LITTLE_PARENS;
                return NULL;
            case '0'...'9':
                brnum = brnum * 10 + c-'0';
                break;
            case ')':
                brnum--;
                done = 1;
                break;
            default:
                rxe->status = RXE_INVALID_CONSTANT;
                return NULL;
        }
    }
    struct rxe_node *node = rxe_new_node(alt);
    if (brnum<0 || brnum >= rxe->brt->nbackrefs) {
        rxe->status = RXE_INVALID_BACKREF;
        return NULL;
    }
    struct rxe *base_rxe = rxe->brt->bkref[brnum];
    if (!(base_rxe->flags & RXE_FLAG_CLOSED_BRACKET)) {
        rxe->status = RXE_RECURSIVE_BACKREF;
        return NULL;
    }
    struct rxe *new_rxe = rxe_deep_clone(base_rxe);
    node->rxe = new_rxe;
    // Remember the group this is a copy of, so a drawing can show (?N) as a
    // single reference back to it rather than redrawing the whole clone.
    node->refers_to = base_rxe;
    node->is_inf = rxe_is_infinite(new_rxe);
    if (node->is_inf) mpz_set_ui(n,1);
    else mpz_set(n,new_rxe->nitems);
    mpz_set(node->nitems,new_rxe->nitems);
    return str;
}

const char *handle_flags(const char *str, int *flags)
{
    if (*str != '?') return str;
    int dir = FLAG_SET;
    while (*str != ':') {
        int flag = 0;
        switch (*str++) {
            case  0 : return NULL;
      case '0'...'9': return --str;
            // Back up onto the ')' so the caller can recognise a group that
            // only sets flags, such as (?i). Returning past it made the caller
            // read the group as a subexpression whose parenthesis never
            // closed, reporting 'missing parentheses' for a valid regex.
            case ')': return --str;
            case 'i': flag = RXE_CASELESS;
                      break;
            // Perl's /s is the one that makes the dot match everything. This
            // arm used to be 'm', so (?s) did nothing and (?m) silently did
            // what (?s) should.
            case 's': flag = RXE_DOTALL;
                      break;
            // /m governs where ^ and $ match. Those are not honoured anywhere
            // in a set enumerator -- the whole regex is implicitly anchored --
            // so accepting it and doing nothing is the correct reading.
            case 'm': break;
            // Not a Perl flag. Perl's inline flags are all lower case, so an
            // upper case letter cannot collide with one, now or later. Lower
            // case 'l' was not available: Perl 5.14 gave it to locale rules.
            case 'L': flag = RXE_LEFT_TO_RIGHT;
                      break;
            case '-': dir = FLAG_RESET;
                      break;
        }
        if (dir == FLAG_SET) 
            *flags |=  flag;
        else
            *flags &= ~flag; 
    }
    return str;
}

// Parse a "{r0,r1}" suffix, str pointing just past the opening brace. On
// success returns a pointer just past the closing brace with the bounds in
// *r0 and *r1; on failure returns NULL with the reason in *status.

static const char *parse_repeat_params(const char *str, int *r0, int *r1,
                                       enum rxe_parse_status *status)
{
    const char *end = strchr(str,'}');
    if (!end) {
        *status = RXE_UNTERMINATED_REPEAT;
        return NULL;
    }
    if (*str<'0' || *str>'9') {
        *status = RXE_BAD_REPETITION;
        return NULL;
    }
    // strtol stops at the closing brace on its own, and unlike atoi it does
    // not overflow silently into a negative count that later drives a wild
    // allocation: a repetition beyond RXE_MAX_REPEAT is refused here. The comma
    // search must be bounded explicitly, though: this used to be done by
    // writing a NUL over the '}', which made rxe_parse scribble on the caller's
    // string and crash outright on a string literal.
    long v = strtol(str,NULL,10);
    if (v > RXE_MAX_REPEAT) { *status = RXE_TOO_BIG; return NULL; }
    *r0 = *r1 = (int)v;
    const char *c = memchr(str,',',end-str);
    if (c) {
        if (c+1 == end) {
            // Nothing after the comma, as in 'a{1,}': no upper bound. Must
            // return here, or the non-digit check below would reject it.
            *r1 = RXE_REP_UNBOUNDED;
            return end+1;
        }
        if (c[1]<'0' || c[1]>'9') {
            *status = RXE_BAD_REPETITION;
            return NULL;
        }
        v = strtol(c+1,NULL,10);
        if (v > RXE_MAX_REPEAT) { *status = RXE_TOO_BIG; return NULL; }
        *r1 = (int)v;
    }
    if (*r0 > *r1) {
        *status = RXE_BAD_REPETITION;
        return NULL;
    }
    return end+1;   // just past the '}'
}

// Move whatever this node holds -- a character class, a subexpression, a
// backreference -- down into a subexpression of its own, leaving the node
// empty and ready to be made into something else. Returns the new
// subexpression, which holds the node's former contents and cardinality.

static struct rxe *demote_node(struct rxe_node *node, int flags)
{
    struct rxe *sub = rxe_new();
    if (flags & RXE_LEFT_TO_RIGHT) sub->flags |= RXE_FLAG_LEFT_TO_RIGHT;
    struct rxe_alt  *alt   = rxe_new_alt(sub);
    struct rxe_node *inner = rxe_new_node(alt);
    inner->len        = node->len;
    inner->str        = node->str;
    inner->rxe        = node->rxe;
    inner->is_backref = node->is_backref;
    inner->is_dict    = node->is_dict;
    inner->nwords     = node->nwords;
    inner->words      = node->words;
    inner->is_inf     = node->is_inf;
    // The body keeps the atom's span and any subroutine referent; the node,
    // becoming the repetition wrapper, has its span stretched over the
    // quantifier by the parse loop and no longer refers on its own.
    inner->src_start  = node->src_start;
    inner->src_end    = node->src_end;
    inner->refers_to  = node->refers_to;
    node->refers_to   = NULL;
    inner->is_repeat  = node->is_repeat;
    inner->rep_min    = node->rep_min;
    inner->rep_max    = node->rep_max;
    inner->rep_count  = node->rep_count;
    inner->rep_alloc  = node->rep_alloc;
    inner->rep_digit  = node->rep_digit;
    mpz_set(inner->nitems,node->nitems);
    mpz_set(alt->nitems,node->nitems);
    mpz_set(sub->nitems,node->nitems);
    if (inner->is_inf) { alt->ninf = 1; sub->ninf = 1; }
    node->len = 0;
    node->str = NULL;
    node->rxe = NULL;
    node->is_backref = 0;
    node->is_dict    = 0;
    node->nwords     = 0;
    node->words      = NULL;
    node->is_inf     = 0;
    node->is_repeat  = 0;
    node->rep_min = node->rep_max = node->rep_count = node->rep_alloc = 0;
    node->rep_digit = NULL;
    return sub;
}

// Turn the node into a repetition of what it currently holds, r0 to r1 times,
// r1 being RXE_REP_UNBOUNDED for no upper limit. This is where the
// representation stops being one copy per position: see repeat.c. Returns 0
// with *status set if the repetition cannot be built.

int build_repeat(struct rxe_node *node, int r0, int r1, int flags,
                 enum rxe_parse_status *status)
{
    // An unbounded repetition whose body can match nothing at all derives
    // the empty string infinitely many ways, so the number of members of any
    // given length is not a number. '(a*)*' is the shape; Perl's matcher
    // refuses an empty loop body for the same reason. This is narrow on
    // purpose: '(\\d+,)*' spends at least two characters per repetition and
    // is perfectly countable, which is the whole point of counting by length.
    if (r1 == RXE_REP_UNBOUNDED && node->rxe && !node->is_backref &&
        rxe_matches_empty(node->rxe)) {
        *status = RXE_NESTED_UNBOUNDED;
        return 0;
    }
    // A variable repetition cannot say which repeat count a backreference
    // into it should mean, so mark the subexpression for
    // handle_backreferences to refuse.
    if (r0 != r1 && node->rxe && !node->is_backref)
        node->rxe->flags |= RXE_FLAG_VARIABLE_REPEAT;
    // A node that is already nothing but a subexpression can be repeated as
    // it stands; anything else has to be demoted into one first, so that the
    // repetition has a single thing to index into.
    if (!node->rxe || node->str || node->is_backref)
        node->rxe = demote_node(node,flags);
    rxe_repeat_make(node,r0,r1);
    return 1;
}

const char *handle_repeats(struct rxe_alt *alt, const char *str,
                           int flags, enum rxe_parse_status *status)
{
    int r0, r1;
    const char *end = parse_repeat_params(str,&r0,&r1,status);
    if (!end) return NULL;
    if (!build_repeat(alt->tail,r0,r1,flags,status)) return NULL;
    return end;
}

// The parameters of a '{{...}}' combinatorial quantifier, 'str' pointing just
// past the second '{'. Forms: '*' (all permutations), 'N', 'N,M' (combinations
// of a size or a range) and the same with a trailing '!' (ordered, i.e.
// permutations). A further trailing '?' quells the base's last node in the last
// item -- the trailing-separator fix. Returns the pointer past the closing
// '}}', or NULL with the status set.
static const char *parse_choose_params(const char *str, int *lo, int *hi,
                                       int *perm, int *star, int *chop,
                                       enum rxe_parse_status *status)
{
    const char *p = str;
    *perm = 0; *star = 0; *lo = 0; *hi = 0; *chop = 0;
    if (*p == '*') {
        *star = 1; *perm = 1; p++;
    } else {
        if (*p < '0' || *p > '9') { *status = RXE_BAD_CHOOSE; return NULL; }
        long v = 0;
        while (*p >= '0' && *p <= '9') {
            v = v*10 + (*p-'0'); if (v > 1000000000L) v = 1000000000L; p++;
        }
        *lo = *hi = (int)v;
        if (*p == ',') {
            p++;
            if (*p < '0' || *p > '9') { *status = RXE_BAD_CHOOSE; return NULL; }
            long w = 0;
            while (*p >= '0' && *p <= '9') {
                w = w*10 + (*p-'0'); if (w > 1000000000L) w = 1000000000L; p++;
            }
            *hi = (int)w;
        }
    }
    if (*p == '!') { *perm = 1; p++; }
    if (*p == '?') { *chop = 1; p++; }
    if (p[0] != '}' || p[1] != '}') { *status = RXE_BAD_CHOOSE; return NULL; }
    if (!*star && *lo > *hi) { *status = RXE_BAD_CHOOSE; return NULL; }
    return p + 2;
}

// The fixed rendered width of a subexpression (every alternation the same fixed
// width) or -1 if it varies. Used to size the '?' chop.
static int node_render_width(struct rxe_node *node);
static int rxe_fixed_width(struct rxe *rxe)
{
    int w = -1;
    for (struct rxe_alt *a = rxe->head; a; a = a->next) {
        int aw = 0;
        for (struct rxe_node *n = a->head; n; n = n->next) {
            int nw = node_render_width(n);
            if (nw < 0) return -1;
            aw += nw;
        }
        if (w < 0) w = aw; else if (w != aw) return -1;
    }
    return w;
}

// The fixed rendered width of one node, or -1 if it is not fixed-width. A
// character class renders one byte; a dictionary is fixed only if its words are
// all the same length; a group recurses; an exact {k} repeat is k copies. A
// variable repeat, another choice, a backref, or an endless node is not fixed.
static int node_render_width(struct rxe_node *node)
{
    if (node->is_inf || node->is_backref || node->is_comb || node->is_shuffle)
        return -1;
    if (node->is_repeat) {
        if (node->rep_min != node->rep_max || !node->rxe) return -1;
        int bw = rxe_fixed_width(node->rxe);
        return bw < 0 ? -1 : bw * node->rep_min;
    }
    if (node->is_dict) {
        int L = -1;
        for (int i = 0; i < node->nwords; i++) {
            int wl = (int)strlen(node->words[i]);
            if (L < 0) L = wl; else if (L != wl) return -1;
        }
        return L < 0 ? 0 : L;
    }
    if (node->rxe) return rxe_fixed_width(node->rxe);   // a group
    return node->len ? 1 : 0;                           // a character class
}

// The chop width of a '{{...?}}': every alternation of the base must end in a
// node of the same fixed width -- the separator quelled from the last item.
// Returns the width (>= 0), or -1 if it cannot be a fixed chop.
static int choose_chop_width(struct rxe *base)
{
    int c = -1;
    for (struct rxe_alt *a = base->head; a; a = a->next) {
        if (!a->tail) return -1;                        // an empty branch
        int w = node_render_width(a->tail);
        if (w < 0) return -1;
        if (c < 0) c = w; else if (c != w) return -1;   // branches disagree
    }
    return c;
}

// Turn the preceding node into a combination or permutation over its members.
// Like build_repeat, it demotes whatever the node holds into a subexpression
// first so the choice has one thing to index into. The base must be finite.
static int build_choose(struct rxe_node *node, int lo, int hi, int perm,
                        int star, int chop, int flags, enum rxe_parse_status *status)
{
    if (node->is_inf ||
        (node->rxe && !node->is_backref && rxe_is_infinite(node->rxe))) {
        *status = RXE_CHOOSE_INFINITE;
        return 0;
    }
    if (!node->rxe || node->str || node->is_backref)
        node->rxe = demote_node(node,flags);
    if (star) {
        // The full permutation: the size is the base's own cardinality, which
        // has to be a number small enough to name a run of that many members.
        if (!mpz_fits_slong_p(node->rxe->nitems) ||
            mpz_cmp_ui(node->rxe->nitems,1000000000UL) > 0) {
            *status = RXE_BAD_CHOOSE;
            return 0;
        }
        lo = hi = (int)mpz_get_ui(node->rxe->nitems);
    }
    rxe_comb_make(node,lo,hi,perm);
    if (chop) {
        int c = choose_chop_width(node->rxe);
        if (c < 0) { *status = RXE_CHOP_VARIABLE; return 0; }
        node->comb_chop = c;
    }
    return 1;
}

// A [:name:] dictionary reference, 'str' pointing at the ':' just inside the
// '['. A POSIX class name expands to an ordinary character class; any other
// name is a word dictionary, resolved through the registry. Returns the
// pointer past the closing ']', or NULL with rxe->status set.

const char *handle_dictionary(struct rxe *rxe, struct rxe_alt *alt, mpz_t ret,
                              const char *str, int flags)
{
    const char *name = str+1;              // past the ':'
    const char *end = name;
    while (*end && !(end[0]==':' && end[1]==']')) end++;
    if (!*end) { rxe->status = RXE_UNTERMINATED_DICT; return NULL; }
    int len = (int)(end - name);
    const char *posix = rxe_posix_class(name,len);
    if (posix) {
        // A single-character class: hand its body to the ordinary machinery,
        // which builds a normal node and applies caseless and the rest. Its
        // return points into the synthetic string; the real advance is past
        // the "[:name:]" here.
        int bl = (int)strlen(posix);
        char *body = NEW(bl+2,char);
        memcpy(body,posix,bl);
        body[bl] = ']';
        body[bl+1] = 0;
        const char *r = handle_character_class(rxe,alt,ret,body,flags);
        rxe_mem_free(body);
        if (!r) return NULL;               // status already set
        return end+2;                      // past the ":]"
    }
    char **words;
    int nwords;
    if (!rxe_lookup_dict(name,len,&words,&nwords)) {
        rxe->status = RXE_UNKNOWN_DICT;
        return NULL;
    }
    struct rxe_node *node = rxe_new_node(alt);
    node->is_dict = 1;
    node->words = words;                   // borrowed from the registry
    node->nwords = nwords;
    mpz_set_ui(node->nitems,nwords);
    mpz_set_ui(ret,nwords);
    return end+2;
}

// Mark, in used[], the members of a bracket-class body such as "0-9]" or
// "^ \t]" -- the strings backslash_letters holds for \d, \w, \s and their
// negations. Only what those bodies contain is handled: literal bytes, a-b
// ranges, and a leading ^ that inverts the whole set. count is advanced for
// each byte newly added, so the caller's running tally and the outer negation
// stay correct.
static void class_mark_body(const char *body, char *used, int *count)
{
    char set[256];
    int  i, inv = 0, do_range = 0;
    unsigned char prev = 0;

    for (i = 0; i < 256; i++) set[i] = 0;
    if (*body == '^') { inv = 1; body++; }
    for (; *body && *body != ']'; body++) {
        unsigned char ch = (unsigned char)*body;
        if (ch == '-' && prev && body[1] && body[1] != ']') {
            do_range = 1;
            continue;
        }
        if (do_range) {
            for (i = prev; i <= ch; i++) set[i] = 1;
            do_range = 0;
            prev = 0;
        } else {
            set[ch] = 1;
            prev = ch;
        }
    }
    for (i = 0; i < 256; i++)
        if ((set[i] ^ inv) && !used[i]) {
            used[i] = 1;
            (*count)++;
        }
}

const char *handle_character_class(
    struct rxe *rxe,
    struct rxe_alt *alt,
    mpz_t ret,
    const char *str,
    int flags
) {
    int  count  = 0;
    int  invert = 0;
    char prev   = 0;
    char c;
    struct rxe_node *node = rxe_new_node(alt);
    char used[256];
    int n,m;
    int range_start,range_finish;
    int do_range = 0;
    // True until the first member has been consumed. Tracked separately from
    // 'prev', which doubles as the low end of a pending range and which the
    // '-' arm below deliberately leaves alone.
    int at_start = 1;
    for (n=0;n<256;n++) used[n] = 0;
    for (;;) {
        c = *str++;
        // A caret inverts the class only as its very first character. Anywhere
        // else it is an ordinary member, so let it reach the default arm
        // below. This is checked before the switch rather than inside it
        // because the default arm cannot be reached by falling through the
        // backslash case, which would misread an escaped caret. The first
        // member position survives it, so "[^]]" is the class without ']'.
        if (c=='^' && at_start && !invert) {
            invert = 1;
            prev = c;
            continue;
        }
        int was_at_start = at_start;
        at_start = 0;
        // Perl and POSIX both read a ']' in the first member position as an
        // ordinary member rather than the end of the class, so "[]]" holds
        // ']' and a bare "[]" is unterminated rather than empty.
        if (c==']' && was_at_start) {
            count++;
            used[(unsigned char)']'] = 1;
            prev = c;
            continue;
        }
        // FIXME: Implement POSIX named character classes
        switch (c) {
             case  0 : // fall-thru
             case ']': if (invert) count = 256-count;
                       mpz_set_ui(ret,count);
                       node->str = NEW(count,char);
                       for (n=m=0;n<256;n++) {
                           if (used[n]^invert) node->str[m++]=n;
                       }
                       node->len = count;
                       mpz_set_ui(node->nitems,count);
                       if (!c) return NULL;
                       return str;
             case '-': if (*str == ']') {
                           count++; used['-']=1;
                           continue;
                       } else {
                           do_range = 1;
                       }
                       continue;
            case '\\': c = *str++;
                       if (!c) return NULL;
                       if (c=='b') {
                           c=8;                    // backspace, not word-boundary
                       } else if (c=='x') {
                           const char *str2 = handle_hex_char(rxe,str,&c);
                           if (!str2) return str;
                           str = str2;
                       } else if (c>='A' && c<='z') {
                           // The same table the top level uses, so \d, \w, \s
                           // and their negations mean the same inside [ ] as
                           // they do bare -- '[\d]' was silently reading as the
                           // letter 'd'.
                           const char *esc = backslash_letters[c-'A'];
                           if (esc && esc[0] && esc[1]) {
                               // A whole class body: a shorthand like \d or \W.
                               // Merge its members; it is a set, not a range end.
                               class_mark_body(esc,used,&count);
                               prev = 0; do_range = 0;
                               continue;
                           }
                           if (esc && esc[0])
                               c = esc[0];         // a control char: \n \t \r ...
                           // else an assertion ("") or unimplemented (NULL):
                           // leave c as the escaped letter, as before.
                       }
                       // fall-thru
              default: range_start  = (do_range ? prev : c)&0xFF;
                       range_finish = c & 0xFF;
                       do_range = 0;
                       for ( n=range_start ; n<=range_finish ; n++ ) {
                           if (!used[n]) {
                               count++; used[n] = 1;
                           }
                           if (flags & RXE_CASELESS) {
                               if ((n>='a' && n<='z') || (n>='A' && n<='Z')) {
                                   if (!used[n^0x20]) {
                                       count++; used[n^0x20] = 1;
                                   }
                               }
                           }
                       }
        }
        prev = c;
    }
}

