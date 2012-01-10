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

#define RXE_FLAG_CLOSED_BRACKET      1

#define FLAG_SET                     1
#define FLAG_RESET                   0

/* -------------------------- Global Declarations ------------------------- */

// Status/error message strings

char *rxe_status_msgs[] = {
    "",
    "infinite",
    "extraneous parentheses",
    "missing parentheses",
    "nothing before quantifier",
    "nested quantifiers",
    "unterminated literal",
    "unterminated character class",
    "unterminated repetition",
    "unterminated flags",
    "bad repetition parameters",
    "unimplemented",
    "invalid backreference",
    "stray non-digit characters in numeric constant",
    "unterminated hex constant",
};

// Backslash-letter escape table.
// Empty string means ignored, NULL means unimplemented, anything else is
// a character or character class to be used instead.
// Some escapes, like \x and \g, are hardcoded and handled before this table
// is looked up.

char *backslash_letters[] = {
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

char *parse(struct rxe *rxe, mpz_t ret, char *str, int flags, int depth);
char *handle_repeats(struct rxe_alt *alt, mpz_t ret, mpz_t x, char *str);
char *handle_character_class(struct rxe *rxe, struct rxe_alt *alt, mpz_t ret, char *str, int flags);
char *handle_flags(char *str, int *flags);
char *handle_recursion(char *str, mpz_t n, struct rxe_alt *alt, struct rxe *rxe);
char *handle_backreferences(char *str, mpz_t n, struct rxe_alt *alt, struct rxe *rxe);
char *handle_hex_char(struct rxe *rxe, char *str, char *chr);

/* ------------------------------------------------------------------------ */

enum rxe_parse_status rxe_error(struct rxe *rxe)
{
    return rxe->status;
}

char *rxe_error_message(struct rxe *rxe)
{
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

char *parse(struct rxe *rxe, mpz_t ret, char *str, int flags, int depth)
{
    mpz_t x,n,p;
    mpz_init_set_ui(x,1);  // Multiplicative accumulator
    mpz_init_set_ui(n,1);  // Current number of elements
    mpz_init_set_ui(p,1);  // Previous n
    char c;
    int i, newflags, quantifier = 0;
    struct rxe_alt *alt = rxe_new_alt(rxe); 
    mpz_set(alt->start,ret);
    struct rxe_node *node;
    char *str2,prev=0;
    for (;;) {
        switch (c = *str++) {
            // ---------------- Termination conditions ---------------
            // End of subexpression
            case ')': if (!depth) {
                          rxe->status = RXE_TOO_MANY_PARENS;
                          return str;
                      }
                      // fall-thru
            // End of string
            case  0 : if (depth && !c) { 
                          rxe->status = RXE_TOO_LITTLE_PARENS;
                          return str;
                      }
                      // fall-thru
            // Alternation: does not really finish; flushes partial
            // results, accumulates them and restarts
            case '|': mpz_mul(x,x,n);
                      mpz_add(ret,ret,x);
                      if (c != '|') return str;
                      // Below runs for alternation only
                      mpz_init_set_ui(x,1);
                      mpz_init_set_ui(n,1);
                      mpz_init_set_ui(p,1);
                      alt = rxe_new_alt(rxe);
                      mpz_set(alt->start,ret);
                      break;
            // ------------------- Sub-expressions -----------------
            case '(': newflags = flags;
                      str2 = handle_flags(str,&newflags);
                      if (!str2) {
                          rxe->status = RXE_UNTERMINATED_FLAGS;
                          return str;
                      }
                      str = str2;
                      if (*str==')') {
                          flags = newflags;
                          str++;
                          continue;
                      }
                      if (*str>='0' && *str<='9' && str[-1]=='?') {
                          str2 = handle_recursion(str,n,alt,rxe);
                          if (!str2) return str;
                          str = str2;
                          break;
                      }
                      if (*str==':') str++;
                      mpz_set_ui(n,0);
                      struct rxe *sub_rxe = rxe_new();
                      node = rxe_new_node(alt);
                      sub_rxe->brt = rxe->brt;
                      rxe_backref_table_add(rxe->brt,sub_rxe);
                      str = parse(sub_rxe,n,str,newflags,depth+1);
                      node->rxe = sub_rxe;
                      mpz_set(node->rxe->nitems,n);
                      mpz_set(node->nitems,n);
                      sub_rxe->flags |= RXE_FLAG_CLOSED_BRACKET;
                      if (sub_rxe->status) {
                          rxe->status = sub_rxe->status;
                          return str;
                      }
                      break;
            // ---------------- Universal quantifiers --------------
            case '*': rxe->status = RXE_INFINITE;
                      return str;
            case '+': rxe->status = RXE_INFINITE;
                      return str;
            // ------------------- Quantifiers ---------------------
            case '?': if (quantifier) {
                          rxe->status = RXE_NESTED_QUANTIFIERS;
                          return str;
                      }
                      if (!alt->tail) {
                          rxe->status = RXE_LONE_QUANTIFIER;
                          return str;
                      }
                      // FIXME: Split handle_repetitions into two functions,
                      // the first which only parses/validades the parameters
                      // and the other that actually does the work. Then
                      // refactor this code using that second function.
                      mpz_set(n,p);
                      mpz_add_ui(n,n,1);
                      mpz_set_ui(p,1);
                      struct rxe *new_rxe = rxe_new();
                      struct rxe_alt *emp_alt = rxe_new_alt(new_rxe);
                      mpz_set(emp_alt->start,alt->tail->start);
                      struct rxe_alt *new_alt = rxe_new_alt(new_rxe);
                      rxe_node_deep_clone(new_alt,alt->tail,1);
                      mpz_add_ui(new_alt->start,alt->tail->start,1);
                      alt->tail->rxe = new_rxe;
                      mpz_set(new_alt->nitems,new_alt->tail->nitems);
                      mpz_add_ui(alt->tail->nitems,new_alt->nitems,1);
                      mpz_set(new_rxe->nitems,alt->tail->nitems);
                      quantifier = 1;
                      break;
            case '{': if (quantifier) {
                          rxe->status = RXE_NESTED_QUANTIFIERS;
                          return str;
                      }
                      if (!alt->tail) {
                          rxe->status = RXE_LONE_QUANTIFIER;
                          return str;
                      }
                      str2 = handle_repeats(alt,n,p,str);
                      if (!str2) {
                          rxe->status = mpz_get_ui(n);
                          return str;
                      }
                      str = str2;
                      mpz_mul(x,x,n);
                      mpz_init_set_ui(n,1);
                      mpz_init_set_ui(p,1);
                      quantifier = 1;
                      break;
            // ----------------- Character Classes -----------------
            case '[': str2 = handle_character_class(rxe,alt,n,str,flags);
                      if (!str2) {
                          rxe->status = RXE_UNTERMINATED_CLASS;
                          return str;
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
                          return str;
                      }
                      c = *str; prev='\\';
                      quantifier = 0;
                      if (c>='0' && c<='9') {
                          str2 = handle_backreferences(str,n,alt,rxe);
                          if (!str2) return str;
                          str = str2;
                          break;
                      }
                      str++;
                      // FIXME: Implement \o, \g with negative numeric
                      // references, \g with named references, \k, etc.
                      if (c == 'x') {
                          str2 = handle_hex_char(rxe,str,&c);
                          if (!str2) return str;
                          str = str2;
                      }
                      else if (c>='A' && c<='z') {
                          char *p = backslash_letters[c-'A'];
                          if (p) {
                              if (c=p[0]) {
                                  if (p[1]) {
                                      handle_character_class(rxe,alt,n,p,0);
                                      break;
                                  } // else fall thru
                              } else {
                                  mpz_set_ui(n,1);
                                  break;
                              }
                          } else {
                             rxe->status = RXE_UNIMPLEMENTED;
                             return str;
                          }
                      }
                      // fall thru
            case '$': if (!*str && prev!='\\') continue;
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

char *handle_hex_char(struct rxe *rxe, char *str, char *chr)
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
            case '0'...'9':
                val = val * 16 + c-'0';
                if (++ndigits==2) done = 1;
                break;
            default:
                str--;
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

char *handle_backreferences(char *str, mpz_t n, struct rxe_alt *alt, struct rxe *rxe)
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
    node->is_backref = 1;
    mpz_set_ui(node->nitems,1);
    mpz_set_ui(n,1);
    return str;
}

char *handle_recursion(char *str, mpz_t n, struct rxe_alt *alt, struct rxe *rxe)
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

char *handle_flags(char *str, int *flags)
{
    if (*str != '?') return str;
    int dir = FLAG_SET;
    while (*str != ':') {
        int flag = 0;
        switch (*str++) {
            case  0 : return NULL;
      case '0'...'9': return --str;
            case ')': return str;
            case 'i': flag = RXE_CASELESS;
                      break;
            case 'm': flag = RXE_DOTALL;
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

char *handle_repeats(struct rxe_alt *alt, mpz_t ret, mpz_t x, char *str)
{
    char *end = strchr(str,'}');
    if (!end) {
        // FIXME: Use something else more elegant to return the status code
        mpz_set_ui(ret,RXE_UNTERMINATED_REPEAT);
        return NULL;
    }
    *end = 0;
    if (*str<'0' || *str>'9') {
        // FIXME: Use something else more elegant to return the status code
        mpz_set_ui(ret,RXE_BAD_REPETITION);
        return NULL;
    }
    int r0  = atoi(str);
    int r1  = r0;
    char *c = strchr(str,',');
    if (c) {
        if (!c[1]) {
            // FIXME: Use something else more elegant to return the status code
            mpz_set_ui(ret,RXE_INFINITE);
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
    struct rxe *new_rxe = rxe_new();
    int n;
    mpz_set_ui(ret,0);
    mpz_t pp;
    mpz_init(pp);
    int shallow = 1;
    for (n=r0;n<=r1;n++) {
        int m;
        struct rxe_alt *new_alt = rxe_new_alt(new_rxe);
        mpz_t p;
        mpz_init(p);
        mpz_pow_ui(p,x,n);
        mpz_add(new_alt->start,prev_node->start,ret);
        mpz_add(ret,ret,p);
        for (m=0;m<n;m++) {
            rxe_node_deep_clone(new_alt,prev_node,shallow);
            shallow = 0;
        }
        if (new_alt->tail) 
            mpz_set(new_alt->nitems,new_alt->tail->nitems);
        else
            mpz_set_ui(new_alt->nitems,0);
        mpz_set(pp,p);
    }
    mpz_set(new_rxe->nitems,ret);
    mpz_set(prev_node->nitems,ret);
    prev_node->rxe = NULL;
    rxe_free_node_data(prev_node);
    prev_node->rxe = new_rxe;
    *end++ = '}';
    return end;
}

char *handle_character_class(
    struct rxe *rxe, 
    struct rxe_alt *alt, 
    mpz_t ret, 
    char *str, 
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
    for (n=0;n<256;n++) used[n] = 0;
    for (;;) {
        c = *str++;
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
             case '^': if (!prev) invert = 1;
                       break;
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
                           char *str2 = handle_hex_char(rxe,str,&c);
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

