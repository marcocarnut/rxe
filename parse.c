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

#include "rxe.h"
#include "rxe_alt.h"
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

const char *parse(struct rxe *rxe, mpz_t ret, const char *str, int flags, int depth);
const char *handle_repeats(struct rxe_alt *alt, mpz_t ret, mpz_t x, const char *str, int flags);
const char *handle_character_class(struct rxe *rxe, struct rxe_alt *alt, mpz_t ret, const char *str, int flags);
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

const char *parse(struct rxe *rxe, mpz_t ret, const char *str, int flags, int depth)
{
    mpz_t x,n,p;
    mpz_init_set_ui(x,1);  // Multiplicative accumulator
    mpz_init_set_ui(n,1);  // Current number of elements
    mpz_init_set_ui(p,1);  // Previous n
    char c;
    int i, newflags, is_flag_group, quantifier = 0;
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
                      // x is now this alternation's cardinality. Record it:
                      // enumeration needs to tell an alternation that matches
                      // nothing (product zero) from one that matches only the
                      // empty string (product one, no nodes).
                      mpz_set(alt->nitems,x);
                      mpz_add(ret,ret,x);
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
                          break;
                      }
                      if (*str==':') str++;
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
                      str = parse(sub_rxe,n,str,newflags,depth+1);
                      node->rxe = sub_rxe;
                      mpz_set(node->rxe->nitems,n);
                      mpz_set(node->nitems,n);
                      sub_rxe->flags |= RXE_FLAG_CLOSED_BRACKET;
                      if (sub_rxe->status) {
                          rxe->status = sub_rxe->status;
                          return parse_done(x,n,p,str);
                      }
                      break;
            // ---------------- Universal quantifiers --------------
            case '*': rxe->status = RXE_INFINITE;
                      return parse_done(x,n,p,str);
            case '+': rxe->status = RXE_INFINITE;
                      return parse_done(x,n,p,str);
            // ------------------- Quantifiers ---------------------
            case '?': if (quantifier) {
                          rxe->status = RXE_NESTED_QUANTIFIERS;
                          return parse_done(x,n,p,str);
                      }
                      if (!alt->tail) {
                          rxe->status = RXE_LONE_QUANTIFIER;
                          return parse_done(x,n,p,str);
                      }
                      // FIXME: Split handle_repetitions into two functions,
                      // the first which only parses/validades the parameters
                      // and the other that actually does the work. Then
                      // refactor this code using that second function.
                      mpz_set(n,p);
                      mpz_add_ui(n,n,1);
                      mpz_set_ui(p,1);
                      struct rxe *new_rxe = rxe_new();
                      if (flags & RXE_LEFT_TO_RIGHT)
                          new_rxe->flags |= RXE_FLAG_LEFT_TO_RIGHT;
                      struct rxe_alt *emp_alt = rxe_new_alt(new_rxe);
                      mpz_set(emp_alt->start,alt->tail->start);
                      mpz_set_ui(emp_alt->nitems,1);   // matches the empty string
                      struct rxe_alt *new_alt = rxe_new_alt(new_rxe);
                      rxe_node_deep_clone(new_alt,alt->tail,1);
                      mpz_add_ui(new_alt->start,alt->tail->start,1);
                      // The clone has taken over this node's characters and
                      // any subexpression, so drop them from the node itself.
                      // Leaving both in place makes rxe_iterate step the
                      // node's own characters as well as the alternation
                      // below it, multiplying the set instead of replacing
                      // it. handle_repeats does the same for {n,m}.
                      alt->tail->rxe = NULL;
                      rxe_free_node_data(alt->tail);
                      alt->tail->rxe = new_rxe;
                      mpz_set(new_alt->nitems,new_alt->tail->nitems);
                      mpz_add_ui(alt->tail->nitems,new_alt->nitems,1);
                      mpz_set(new_rxe->nitems,alt->tail->nitems);
                      quantifier = 1;
                      break;
            case '{': if (quantifier) {
                          rxe->status = RXE_NESTED_QUANTIFIERS;
                          return parse_done(x,n,p,str);
                      }
                      if (!alt->tail) {
                          rxe->status = RXE_LONE_QUANTIFIER;
                          return parse_done(x,n,p,str);
                      }
                      str2 = handle_repeats(alt,n,p,str,flags);
                      if (!str2) {
                          rxe->status = mpz_get_ui(n);
                          return parse_done(x,n,p,str);
                      }
                      str = str2;
                      mpz_mul(x,x,n);
                      mpz_set_ui(n,1);   // already live; assign, do not re-init
                      mpz_set_ui(p,1);
                      quantifier = 1;
                      break;
            // ----------------- Character Classes -----------------
            case '[': str2 = handle_character_class(rxe,alt,n,str,flags);
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
        rxe->status = RXE_INFINITE;
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
        rxe->status = RXE_INFINITE;
        return NULL;
    }
    struct rxe *new_rxe = rxe_deep_clone(base_rxe);
    node->rxe = new_rxe;
    mpz_set(node->nitems,new_rxe->nitems);
    mpz_set(n,new_rxe->nitems);
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

const char *handle_repeats(struct rxe_alt *alt, mpz_t ret, mpz_t x, const char *str, int flags)
{
    const char *end = strchr(str,'}');
    if (!end) {
        // FIXME: Use something else more elegant to return the status code
        mpz_set_ui(ret,RXE_UNTERMINATED_REPEAT);
        return NULL;
    }
    if (*str<'0' || *str>'9') {
        // FIXME: Use something else more elegant to return the status code
        mpz_set_ui(ret,RXE_BAD_REPETITION);
        return NULL;
    }
    // atoi stops at the closing brace on its own. The comma search must be
    // bounded explicitly, though: this used to be done by writing a NUL over
    // the '}' and restoring it afterwards, which made rxe_parse scribble on
    // the caller's string and crash outright on a string literal.
    int r0  = atoi(str);
    int r1  = r0;
    const char *c = memchr(str,',',end-str);
    if (c) {
        if (c+1 == end) {
            // Nothing after the comma, as in a{1,}: an open-ended repetition,
            // which denotes an infinite set. Must return here, or the
            // non-digit check below overwrites this with a less accurate one.
            // FIXME: Use something else more elegant to return the status code
            mpz_set_ui(ret,RXE_INFINITE);
            return NULL;
        }
        if (c[1]<'0' || c[1]>'9') {
            // FIXME: Use something else more elegant to return the status code
            mpz_set_ui(ret,RXE_BAD_REPETITION);
            return NULL;
        }
        r1 = atoi(c+1);
    }
    if (r0>r1) {
        // FIXME: Use something else more elegant to return the status code
        mpz_set_ui(ret,RXE_BAD_REPETITION);
        return NULL;
    }
    struct rxe_node *prev_node = alt->tail;
    // A variable repetition builds one alternation per repeat count, each with
    // a different number of clones. Only one of them can alias the original
    // subexpression, so a later \N -- which resolves through that single alias
    // -- would read from an alternation that is not the one being enumerated.
    // Mark the subexpression so handle_backreferences can refuse it.
    if (r0 != r1 && prev_node->rxe)
        prev_node->rxe->flags |= RXE_FLAG_VARIABLE_REPEAT;
    struct rxe *new_rxe = rxe_new();
    // The repeated copies live in an alternation of their own, so the
    // direction has to reach this subexpression as well, or {n} would keep
    // counting right to left inside a (?L) group.
    if (flags & RXE_LEFT_TO_RIGHT) new_rxe->flags |= RXE_FLAG_LEFT_TO_RIGHT;
    int n;
    mpz_set_ui(ret,0);
    // Declared out here and reused: initialising it inside the loop leaked one
    // allocation per repeat count, which for a wide range is a great many.
    mpz_t p;
    mpz_init(p);
    for (n=r0;n<=r1;n++) {
        int m;
        struct rxe_alt *new_alt = rxe_new_alt(new_rxe);
        mpz_pow_ui(p,x,n);
        mpz_add(new_alt->start,prev_node->start,ret);
        mpz_add(ret,ret,p);
        for (m=0;m<n;m++) {
            // Exactly one clone may alias the original subexpression rather
            // than deep-copying it; it inherits ownership of it. Make that the
            // *last* clone, so a \N resolving through the backreference table
            // -- which still points at the original -- refers to the final
            // repetition, as Perl does.
            rxe_node_deep_clone(new_alt,prev_node,n==r1 && m==n-1);
        }
        // p is x^n, the cardinality of this repeat count. For n==0 that is 1,
        // the empty string, which is a member and must not be mistaken for an
        // alternation that matches nothing.
        mpz_set(new_alt->nitems,p);
    }
    mpz_clear(p);
    mpz_set(new_rxe->nitems,ret);
    mpz_set(prev_node->nitems,ret);
    // Exactly one clone aliases the original subexpression and inherits it, so
    // it must not be freed here. That clone only exists when at least one was
    // made: for {0} the loop above bodies out without cloning anything, and
    // this node then holds the only pointer to the subexpression.
    if (r1 > 0) prev_node->rxe = NULL;
    rxe_free_node_data(prev_node);
    prev_node->rxe = new_rxe;
    return end+1;   // just past the '}'
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
                           c=8;
                       } else if (c=='x') {
                           const char *str2 = handle_hex_char(rxe,str,&c);
                           if (!str2) return str;
                           str = str2;
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

