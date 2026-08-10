/* [KSC4]-------------------------------------------------------------------[]
 * 
 *  rxenum - Count size and enumerate sets specified as regular expressions
 *           Version 1.0.0 by kiko at postcogito dot org, first released 2011
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
 * []-----------------------------------------------------------------------[]
 */

#include <stdio.h>
#include <getopt.h>
#include <stdarg.h>
#include <math.h>
#include <string.h>
#include <stdlib.h>
#include "rxe.h"

/* ------------------------ Macro-Defined Constants ----------------------- */

#define ENUM_ONCE                    1
#define ENUM_NUMBER                  2

// Longest element this program will print. Anything longer is truncated, and
// silently, which is why the buffer is far larger than the hundred bytes it
// held while a repetition of more than a few thousand could not be built at
// all. Half a page: nothing sensible reaches it, and it still costs one stack
// frame rather than an allocation.

#define MAXSTRLEN                 2048

/* -------------------------- Global Declarations ------------------------- */

/* -------------------------- Function Prototypes ------------------------- */

void print_grouped(FILE *fp, char *prefix, mpz_t x, char *suffix, char sep);
void die(int code, char *msg, ...);
void enumerate(struct rxe *rxe, int flags, int offset, mpz_t from, mpz_t cnt,
               char sep, struct rxe_permutation *perm);
int mpz_len(mpz_t x);

/* --------------------------- Dictionary Loading ------------------------- */

// Where to look for a "name.dict" file: the directories named by -D, in
// order, then the current one. A dictionary is a plain text file, one word
// per line; trailing carriage returns and newlines are trimmed so a file
// saved on either kind of system reads the same.

#define MAX_DICT_DIRS 16
static const char *dict_dirs[MAX_DICT_DIRS];
static int         ndict_dirs;

// The render buffer's size, and so the longest member a line of output can
// hold before it is truncated. This is the display width, distinct from the
// library's rxe_max_member cap on what may be built at all: a member can be
// legal to materialise yet longer than one wants printed. Settable with -w.
static int str_width = MAXSTRLEN;

static char **load_dict_file(const char *path, int *nwords)
{
    FILE *fp = fopen(path,"rb");
    if (!fp) return NULL;
    int cap = 64, n = 0;
    char **words = malloc(cap*sizeof(char *));
    char line[1024];
    while (fgets(line,sizeof(line),fp)) {
        int len = strlen(line);
        while (len && (line[len-1]=='\n' || line[len-1]=='\r')) line[--len]=0;
        if (n==cap) { cap*=2; words = realloc(words,cap*sizeof(char *)); }
        words[n] = malloc(len+1);
        memcpy(words[n],line,len+1);
        n++;
    }
    fclose(fp);
    *nwords = n;
    return words;
}

// The resolver the library calls when it meets an unknown [:name:]. Tries each
// search directory in turn; registers the words with the library, which keeps
// its own copy, so these can be freed straight away. Returns 1 if it found a
// file, 0 otherwise -- which the library turns into "unknown dictionary".

static int dict_resolver(const char *name)
{
    int d;
    for (d = -1 ; d < ndict_dirs ; d++) {
        char path[1024];
        const char *dir = d < 0 ? "." : dict_dirs[d];
        snprintf(path,sizeof(path),"%s/%s.dict",dir,name);
        int nwords;
        char **words = load_dict_file(path,&nwords);
        if (!words) continue;
        rxe_register_dict(name,(const char **)words,nwords);
        int i;
        for (i=0;i<nwords;i++) free(words[i]);
        free(words);
        return 1;
    }
    return 0;
}

/* ------------------------------ Main Program ---------------------------- */

int main(int argc, char **argv)
{
    if (argc<2) {
        die(0,"Usage: rxenum [-isLnezr] [-k key] [-c count] [-f from] [-t to] [-M bytes] [-w width] <regex>\n");
    }
    int flags = 0;
    int do_enumerate = 0;
    int options = 0;
    int offset = 1;
    int have_from = 0;
    int have_to = 0;
    int have_random = 0;
    int report_order = 0;
    char *key = NULL;
    char sep = ',';
    mpz_t from,to,count;
    mpz_init(from);
    mpz_init(to);
    mpz_init(count);
    rxe_set_dict_resolver(dict_resolver);
    // Free the dictionary registry however the program leaves, so a run that
    // exits early -- a random pick, an order query, an error -- does not leak
    // it under a leak checker.
    atexit(rxe_free_dicts);
    for (;;) {
        int o = getopt(argc,argv,"isLenzf:t:c:r.,_~k:QD:M:w:");
        if (o < 0) break;
        switch(o) {
            case 'i': flags |= RXE_CASELESS;
                      break;
            case 's': flags |= RXE_DOTALL;
                      break;
            case 'L': flags |= RXE_LEFT_TO_RIGHT;
                      break;
            case 'n': options |= ENUM_NUMBER;
                      do_enumerate = 1;
                      break;
            case 'z': offset = 0;
                      break;
            case 't': have_to = 1;
                      // fall-thru
            case 'c': mpz_set_str(count,optarg,10);
                      if (mpz_sgn(count)<=0) 
                          die(1,"count must be strictly positive\n");
                      // fall-thru
            case 'e': do_enumerate = 1;
                      break;
            case 'f': mpz_set_str(from,optarg,10);
                      have_from = 1;
                      mpz_set_ui(count,1);
                      do_enumerate = 1;
                      break;
            case 'r': have_random = 1;
                      break;
            case 'Q': report_order = 1;
                      break;
            case 'D': if (ndict_dirs < MAX_DICT_DIRS)
                          dict_dirs[ndict_dirs++] = optarg;
                      break;
            case 'k': key = optarg;
                      do_enumerate = 1;
                      break;
            case 'M': rxe_set_max_member(strtoul(optarg,NULL,10));
                      break;
            case 'w': str_width = atoi(optarg);
                      if (str_width < 1) die(1,"-w needs a positive width\n");
                      break;
            case ',':
            case '_':
            case '.': sep = o;
                      break;
            case '~': sep = 0;
                      break;
             default: die(1,"Unknown option '%c'\n",o);
                      exit(1);
        }
    }

    struct rxe *rxe;
    if (!argv[optind]) die(1,"missing regex\n");
    // GNU getopt reorders argv so that options may follow the regex; the musl
    // and BSD ones stop at the first thing that is not an option, as POSIX
    // says. That difference used to make 'rxenum -z <regex> -f 3999' quietly
    // ignore the -f and print a count instead, which is a worse answer than
    // refusing. The usage line has always put the options first.
    if (argv[optind+1])
        die(1,"unexpected argument '%s': options must come before the regex\n",
            argv[optind+1]);
    rxe = rxe_parse(argv[optind],flags);
    if (rxe_error(rxe)) {
        const char *pat = argv[optind];
        int pos = rxe_error_pos(rxe), len = (int)strlen(pat);
        if (pos < 0) pos = 0;
        if (pos > len) pos = len;
        fprintf(stderr,"%s\n",rxe_error_message(rxe));   // line 1 unchanged
        fprintf(stderr,"    %s\n",pat);
        fprintf(stderr,"    %*s^\n",pos,"");
        exit(1);
    }

    if (report_order) {
        // Which of the two orders this expression is enumerated in. Used by
        // the test suite to know which invariants apply; see ENUMERATION
        // ORDER in the manual page.
        printf("%s\n", rxe_is_shortlex(rxe) ? "shortlex" :
                        rxe_is_infinite(rxe) ? "diagonal" : "place value");
        rxe_free(rxe);
        mpz_clear(from); mpz_clear(to); mpz_clear(count);
        return 0;
    }
    if (have_random && key)
        die(1,"-r and -k are mutually exclusive: -k already visits every "
              "member exactly once\n");

    if (rxe_is_infinite(rxe)) {
        // Both need a domain to work over, and there is not one.
        if (key)        die(1,"-k needs a finite set to permute\n");
        if (have_random) die(1,"-r needs a finite set to choose from\n");
    }
    struct rxe_permutation *perm = NULL;
    if (key) perm = rxe_permutation_new(rxe->nitems,key);

    if (have_random) {
        if (!mpz_sgn(rxe->nitems))
            die(1,"the set is empty, there is nothing to choose from\n");
        gmp_randstate_t state;
        gmp_randinit_mt(state);
        FILE *fp = fopen("/dev/urandom","rb");
        if (!fp) die(1,"unable to open /dev/urandom\n");
        // Seed from one block of entropy. The loop this replaces called
        // gmp_randseed_ui 32 times over, each call discarding the seed set by
        // the one before, so only the final word ever had any effect.
        unsigned char seed_bytes[32];
        if (fread(seed_bytes,1,sizeof(seed_bytes),fp) != sizeof(seed_bytes))
            die(1,"unable to read from /dev/urandom\n");
        fclose(fp);
        mpz_t seed;
        mpz_init(seed);
        mpz_import(seed,sizeof(seed_bytes),1,1,0,0,seed_bytes);
        gmp_randseed(state,seed);
        mpz_clear(seed);
        if (!mpz_sgn(count)) mpz_set_ui(count,1);
        mpz_t zero;
        mpz_init(zero);
        for (;;) {
            mpz_urandomm(from,state,rxe->nitems);
            // enumerate() takes a number in the caller's numbering, which
            // starts at 'offset', and subtracts it back off. Without this the
            // random choice was one too low, and could be -1: seeking to that
            // used to leave the expression at whatever it already held, so
            // '-r' quietly returned the first element instead of failing.
            mpz_add_ui(from,from,offset);
            enumerate(rxe,options|ENUM_ONCE,offset,from,zero,sep,NULL);
            mpz_sub_ui(count,count,1);
            if (!mpz_sgn(count)) {
                mpz_clear(zero);
                mpz_clear(from);
                mpz_clear(to);
                mpz_clear(count);
                gmp_randclear(state);
                rxe_free(rxe);
                return 0;
            }
        }
    }
    if (!have_from) mpz_set_ui(from,offset);
    if (have_to) {
        mpz_sub(count,count,from);
        mpz_add_ui(count,count,1);
        if (mpz_sgn(count)<=0) 
            die(1,"start point must be before finish\n");
    }
    if (mpz_cmp_ui(from,offset)<0) {
        die(1,"start point can't be less than %d\n",offset);
    }
    
    if (do_enumerate) {
        // An empty set enumerates to nothing at all; there is no element to
        // seek to, so skip straight past. An infinite one always has a first
        // element however empty its finite part is.
        if (mpz_sgn(rxe->nitems) || rxe_is_infinite(rxe))
            enumerate(rxe,options,offset,from,count,sep,perm);
    } else if (rxe_is_infinite(rxe)) {
        // There is no number to print. Say so rather than print the size of
        // the finite part, which would be a smaller number than the truth by
        // an unbounded amount.
        printf("infinite\n");
    } else {
        print_grouped(stdout,NULL,rxe->nitems,"\n",sep);
        // The logarithms are meaningless for an empty set, and log(0) is
        // -infinity, which mpz_pow_ui turns into a GMP abort.
        if (mpz_sgn(rxe->nitems)) {
            // Take the base-two logarithm from the number's own scale rather
            // than by converting it to a double. mpz_get_d overflows to
            // infinity past about 1.8e308 -- a mere 309 digits, which this
            // library reaches constantly -- and infinity then flows into the
            // exponent of mpz_pow_ui below, where the cast to unsigned long is
            // undefined: on one platform it yielded a harmless value, on
            // another an astronomical one that made GMP allocate until it
            // aborted. mpz_get_d_2exp returns a mantissa in [0.5,1) and the
            // binary exponent separately, so the logarithm is exact in its
            // integer part however large the number.
            signed long e2;
            double mant = mpz_get_d_2exp(&e2,rxe->nitems);
            double log2 = log(mant)/log(2) + (double)e2;
            int n, base[] = { 10, 2 };
            double per[] = { log2*log(2)/log(10), log2 };
            int nbases = sizeof(base)/sizeof(base[0]);
            for (n=0;n<nbases;n++) {
                double l = per[n];
                // Round to the nearest integer exponent and test exactness
                // against base^that. l is finite now, so the exponent is a
                // sane count -- a few tens of thousands at most -- and the
                // power is cheap to form; it was only the infinite exponent
                // that was ruinous.
                unsigned long e = (l >= 0 && l < 1e9) ? (unsigned long)(l+0.5) : 0;
                mpz_t num,b;
                mpz_init(num);
                mpz_init_set_ui(b,base[n]);
                mpz_pow_ui(num,b,e);
                printf("%s ", mpz_cmp(rxe->nitems,num) ? "~" : "=");
                printf("%2d^%g\n",base[n],l);
                mpz_clear(num);
                mpz_clear(b);
            }
        }
    }
    //rxe_backref_table_free(rxe->brt);
    rxe_permutation_free(perm);
    rxe_free(rxe);
    mpz_clear(from);
    mpz_clear(to);
    mpz_clear(count);
    return 0;
}

void enumerate(struct rxe *rxe, int flags, int offset, mpz_t from, mpz_t cnt,
               char sep, struct rxe_permutation *perm)
{
    mpz_t final;
    mpz_init(final);
    if (mpz_sgn(cnt)) {
        mpz_add(final,from,cnt);
        mpz_sub_ui(final,final,1);
    } else if (rxe_is_infinite(rxe)) {
        // No last element to count digits up to. Leave room for a wide
        // number: this only sizes the field the index is printed in.
        mpz_set_ui(final,1000000000);
    } else {
        mpz_set(final,rxe->nitems);
    }
    mpz_sub_ui(final,final,1-offset);
    int nd = mpz_len(final);
    nd += (nd-1)/3-1;
    int nd0 = mpz_len(from);
    nd -= nd0+(nd0-1)/3-1;
    mpz_t count,step1,step2;
    mpz_init_set(count,from);
    mpz_t q;
    mpz_init(q);
    mpz_init_set_ui(step1,10);
    mpz_cdiv_q(q,count,step1);
    mpz_mul(step1,step1,q);
    if (!mpz_sgn(step1)) mpz_set_ui(step1,10);
    mpz_init_set_ui(step2,1000);
    mpz_cdiv_q(q,count,step2);
    mpz_mul(step2,step2,q);
    if (!mpz_sgn(step2)) mpz_set_ui(step2,1000);
    mpz_sub_ui(from,from,offset);
    // With a permutation the odometer cannot simply be stepped: consecutive
    // output positions are scattered across the set, so each one is reached
    // by seeking to the permuted index. rxe_permutation_map is the identity
    // when perm is NULL, so the unpermuted path is unchanged.
    mpz_t idx,target;
    mpz_init_set(idx,from);
    mpz_init(target);
    if (perm && mpz_cmp(idx,rxe->nitems)>=0) die(100,"seek past end");
    rxe_permutation_map(target,perm,idx);
    // A seek can fail two ways: the index is past the end of a finite set, or
    // the member it lands on is too large to build. The latch tells them apart.
    rxe_check_overflow();
    if (rxe_seek(rxe,target)) {
        if (rxe_member_overflow) {
            rxe->status = RXE_TOO_BIG;
            die(1,"%s\n",rxe_error_message(rxe));
        }
        die(100,"seek past end");
    }
    char *str = malloc((size_t)str_width + 1);
    if (!str) die(1,"out of memory for a %d-byte render buffer\n",str_width);
    for (;;) {
         rxe_current(str,str_width,rxe);
         if (flags & ENUM_NUMBER) {
            printf("%*s",nd,"");
            print_grouped(stdout,NULL,count," ",sep);
            mpz_add_ui(count,count,1);
            if (!mpz_cmp(count,step1)) {
                nd--; mpz_mul_ui(step1,step1,10);
                if (!mpz_cmp(count,step2)) {
                    nd--; mpz_mul_ui(step2,step2,1000);
                }
            }
         }
         printf("%s\n",str);
         if (perm) {
             mpz_add_ui(idx,idx,1);
             if (mpz_cmp(idx,rxe->nitems)>=0) break;
             rxe_permutation_map(target,perm,idx);
             if (rxe_seek(rxe,target)) break;
         } else {
             if (!rxe_next(rxe)) break;
         }
         if (flags & ENUM_ONCE) break;
         if (mpz_sgn(cnt)) {
             mpz_sub_ui(cnt,cnt,1);
             if (!mpz_sgn(cnt)) break;
         }
    }
    free(str);
    // -r calls this once per sample, so leaving these behind accumulated.
    mpz_clear(idx);
    mpz_clear(target);
    mpz_clear(final);
    mpz_clear(count);
    mpz_clear(step1);
    mpz_clear(step2);
    mpz_clear(q);
}

void print_grouped(FILE *fp, char *prefix, mpz_t x, char *suffix, char sep)
{
    if (prefix) fprintf(fp,"%s",prefix);
    if (mpz_sgn(x)) {
        // Pad the field out to a whole number of three-digit groups, so the
        // loop below -- which counts groups from the left of the padded
        // string -- breaks on real thousands boundaries. mpz_sizeinbase may
        // overshoot by one digit; the extra padding is blank and is skipped.
        // Sizing this from mpz_size() instead yielded a zero-length buffer
        // for x==0, which gmp_sprintf then overran.
        int size = ((mpz_sizeinbase(x,10)+2)/3)*3;
        char str[size+1];
        gmp_sprintf(str,"%*Zd",size,x);
        char *p = str;
        int   i = 2;
        int   f = 0;
        for (;*p;p++) {
            if (++i==3) {
                i=0; if (f && sep) putc(sep,fp);
            }
            if (*p > '0') f=1;
            if (f) putc(*p,fp);
        }
    } else {
        fprintf(fp,"0");
    }
    if (suffix) fprintf(fp,"%s",suffix);
}

// FIXME: perhaps we could replace this by mpz_sizeinbase

int mpz_len(mpz_t x)
{
    mpz_t r;
    mpz_init_set_ui(r,10);
    int len = 0;
    for (;;) {
        len++;
        if (mpz_cmp(r,x)>0) break;
        mpz_mul_ui(r,r,10);
    }
    mpz_clear(r);
    return len;
}

/* ---------------------------- Support Routines -------------------------- */

void die(int code, char *msg, ...)
{
    va_list list_ptr;
    va_start(list_ptr,msg);
    vfprintf(stderr,msg,list_ptr);
    va_end(list_ptr);
    exit(code);
}




