/* [KSC4]-------------------------------------------------------------------[]
 * 
 *  rxenum - Count size and enumerate sets specified as regular expressions
 *           Version 0.9 by kiko at postcogito dot org on 2011-12-23
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
#include "rxe.h"

/* ------------------------ Macro-Defined Constants ----------------------- */

#define ENUM_ONCE                    1
#define ENUM_NUMBER                  2

#define MAXSTRLEN                  100

/* -------------------------- Global Declarations ------------------------- */

/* -------------------------- Function Prototypes ------------------------- */

void print_grouped(FILE *fp, char *prefix, mpz_t x, char *suffix, char sep);
void die(int code, char *msg, ...);
void enumerate(struct rxe *rxe, int flags, int offset, mpz_t from, mpz_t cnt, char sep);
int mpz_len(mpz_t x);

/* ------------------------------ Main Program ---------------------------- */

int main(int argc, char **argv)
{
    if (argc<2) {
        die(0,"Usage: rxenum [-isnezr] [-c count] [-f from] [-t to] <regex>\n");
    }
    int flags = 0;
    int do_enumerate = 0;
    int options = 0;
    int offset = 1;
    int have_from = 0;
    int have_to = 0;
    int have_random = 0;
    char sep = ',';
    mpz_t from,to,count;
    mpz_init(from);
    mpz_init(to);
    mpz_init(count);
    for (;;) {
        int o = getopt(argc,argv,"isenzf:t:c:r.,_~");
        if (o < 0) break;
        switch(o) {
            case 'i': flags |= RXE_CASELESS;
                      break;
            case 's': flags |= RXE_DOTALL;
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
    rxe = rxe_parse(argv[optind],flags);
    if (rxe_error(rxe)) {
        fprintf(stderr,"%s\n",rxe_error_message(rxe));
        exit(1);
    }

    if (have_random) {
        gmp_randstate_t state;
        gmp_randinit_mt(state);
        FILE *fp = fopen("/dev/urandom","rb");
        if (!fp) die(1,"unable to open /dev/rrandom\n");
        int n;
        int size = mpz_size(rxe->nitems)+1;
        for (n=0;n<32;n++) {
            unsigned long int seed;
            fread(&seed,1,sizeof(seed),fp);
            gmp_randseed_ui(state,seed);
        }
        close(fp);
        if (!mpz_sgn(count)) mpz_set_ui(count,1);
        mpz_t zero;
        mpz_init(zero);
        for (;;) {
            mpz_urandomm(from,state,rxe->nitems);
            enumerate(rxe,options|ENUM_ONCE,offset,from,zero,sep);
            mpz_sub_ui(count,count,1);
            if (!mpz_sgn(count)) return 0;
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
        enumerate(rxe,options,offset,from,count,sep);
    } else {
        print_grouped(stdout,NULL,rxe->nitems,"\n",sep);
        double log_d = log(mpz_get_d(rxe->nitems));
        int n, base[] = { 10, 2 };
        int nbases = sizeof(base)/sizeof(base[0]);
        for (n=0;n<nbases;n++) {
            double l = log_d/log(base[n]);
            mpz_t num,b;
            mpz_init(num);
            mpz_init_set_ui(b,base[n]);
            mpz_pow_ui(num,b,l);
            printf("%s ", mpz_cmp(rxe->nitems,num) ? "~" : "=");
            printf("%2d^%g\n",base[n],l);
        }
    }
    //rxe_backref_table_free(rxe->brt);
    rxe_free(rxe);
    return 0;
}

void enumerate(struct rxe *rxe, int flags, int offset, mpz_t from, mpz_t cnt, char sep)
{
    mpz_t final;
    mpz_init(final);
    if (mpz_sgn(cnt)) {
        mpz_add(final,from,cnt);
        mpz_sub_ui(final,final,1);
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
    if (rxe_seek(rxe,from)) die(100,"seek past end");
    for (;;) {
         char str[MAXSTRLEN+1];
         rxe_current(str,MAXSTRLEN,rxe);
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
         if (!rxe_next(rxe)) break;
         if (mpz_sgn(cnt)) {
             mpz_sub_ui(cnt,cnt,1);
             if (!mpz_sgn(cnt)) break;
         }
         if (flags & ENUM_ONCE) break;
    }
}

void print_grouped(FILE *fp, char *prefix, mpz_t x, char *suffix, char sep)
{
    int size = mpz_size(x)*21;
    char str[size+1];
    gmp_sprintf(str,"%*Zd",size,x);
    if (prefix) fprintf(fp,"%s",prefix);
    if (mpz_sgn(x)) {
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
        if (mpz_cmp(r,x)>0) return len;
        mpz_mul_ui(r,r,10);
    }
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




