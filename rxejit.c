/*
 * rxejit - compile a regex-set into C that enumerates it.
 *
 *          rxenum walks the set through the library's interpreter: a tree of
 *          nodes, an mpz index, a function call per member. For a bruteforce --
 *          keycracking, dedup, fuzzing -- that interpreter is the whole cost,
 *          and the benchmark said so. This emits C specialised to one regex
 *          instead: an unrolled odometer over fixed char buffers, incremented
 *          by carry, that the system compiler then optimises. No tree, no mpz,
 *          no indirect call.
 *
 *          Each position of a member is a "wheel": a character class, or an
 *          alternation or bounded repeat baked out by the interpreter. When a
 *          wheel's branches are all one length the member sits at compile-time
 *          offsets, delta-patched as the odometer turns; when they vary
 *          ([a-z]{1,3}, (cat|hi)) the member is rebuilt each step. A
 *          backreference is no wheel at all -- it copies the bytes of the group
 *          it names, tracked in local variables the generated code sets as the
 *          group is laid. A variable-count repeat too large to bake into one
 *          wheel ([a-z]{1,7} is 8 billion) becomes a super-wheel of the odometer
 *          instead: a base-(the body) number whose length grows from a to b. So
 *          masks, alternations even and uneven, subroutines, bounded repeats big
 *          and small, dictionaries, and backreferences all compile -- every
 *          finite pattern. Only an unbounded (infinite) repeat, or an
 *          alternation/dictionary too large to unroll, declines by name, and the
 *          interpreter stays the answer there. It runs the compiled program (or
 *          prints the C with -S) under a chosen sink: write the members, count
 *          them, match them
 *          against a target set (MD5 too, for keycracking), or find duplicates.
 *
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include "rxe.h"
#include "rxejit_rt_embed.h"       // RXEJIT_RT: the runtime, as a C string
#include "rxejit_cl_embed.h"       // RXEJIT_CL: the device runtime for -G
#include "rxe_lay.h"       // regex -> odometer wheels, now in the library


// What the generated loop does with each member. write is the default -- the
// members to stdout, as rxenum -e does; count only tallies them, which times
// the enumeration with no I/O in the way; match probes each against a target
// set loaded at runtime and prints the hits (a mask being a keyspace to sift);
// dup hashes each into a per-thread set and reports the repeats, merged at the
// join -- meaningful now that alternations put duplicates in the set.
enum { SINK_WRITE, SINK_COUNT, SINK_MATCH, SINK_DUP };


// The hash to keycrack against (-H). Everything that differs between them is a
// few facts: the digest length, the runtime function that hashes a candidate on
// the CPU (the oracle, in rxejit_rt.h) and on the GPU (a lane, in rxejit_cl.cl),
// and NTLM's UTF-16LE widening, which halves the candidate width one GPU block
// can hold. The chosen entry is a file-scope pointer the emitters read, like
// 'reason' -- one pattern is compiled per run, so it need not be threaded.
struct hashalg { const char *name; int dglen; int mfac; const char *cpu_fn, *gpu_fn; };
static const struct hashalg HASHES[] = {
    { "md5",    16, 1, "rt_md5",    "cl_md5"    },
    { "ntlm",   16, 2, "rt_ntlm",   "cl_ntlm"   },  // MD4(UTF-16LE): message is 2x
    { "sha1",   20, 1, "rt_sha1",   "cl_sha1"   },
    { "sha256", 32, 1, "rt_sha256", "cl_sha256" },
};
static const struct hashalg *HA = &HASHES[0];


// Print the pattern into a C comment, defusing any */ that would close it.
static void emit_comment(FILE *o, const char *s)
{
    for (; *s; s++) fputc((*s == '*' && s[1] == '/') ? ' ' : *s, o);
}

// Emit the statement that lays wheel i's alternative 'idx' into the buffer at
// 'off': a single byte for a class, a memcpy for a wider alternation branch.
static void emit_lay(FILE *o, int i, int off, int L, const char *idx)
{
    if (L == 1) fprintf(o, "buf[%d] = A%d[%s];", off, i, idx);
    else        fprintf(o, "memcpy(buf + %d, A%d + (%s) * %d, %d);", off, i, idx, L, L);
}

#define DUP_LIST_CAP 10000000L     // most members -d -v will enumerate to list

// How many of a wheel's n alternatives are distinct. Each wheel writes a fixed,
// disjoint slice of the member, so the whole set's distinct count is the product
// of these -- a closed form for dedup, no enumeration, however large the set.
static int g_cmpL;
static int cmp_alt(const void *a, const void *b)
{
    return memcmp(*(const char *const *)a, *(const char *const *)b, (size_t)g_cmpL);
}
static int wheel_distinct(const struct wheel *w)
{
    if (w->n <= 1) return w->n;
    const char **p = malloc((size_t)w->n * sizeof *p);
    if (!p) return w->n;                       // can't check; assume distinct
    for (int i = 0; i < w->n; i++) p[i] = w->base + (size_t)i * w->L;
    g_cmpL = w->L;
    qsort(p, w->n, sizeof *p, cmp_alt);
    int d = 1;
    for (int i = 1; i < w->n; i++) if (memcmp(p[i], p[i-1], (size_t)w->L)) d++;
    free(p);
    return d;
}

// A pure non-negative integer literal (a fixed member length), else -1 -- so the
// baked single-block hash below fires only when the length is known at codegen.
static int const_int(const char *s)
{
    if (!s || !*s) return -1;
    for (const char *p = s; *p; p++) if (*p < '0' || *p > '9') return -1;
    return atoi(s);
}

static const unsigned char MD5S[64] = {
    7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
    5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
    4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
    6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21 };
static const unsigned MD5K[64] = {
    0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
    0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
    0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
    0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
    0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
    0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
    0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
    0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391 };

// A specialised MD5 for a compile-time member length (one block, len <= 55): the
// message words are baked from buf with the 0x80 pad and the bit length folded
// in as constants, and all 64 rounds are unrolled with K/S/g as literals -- no
// call, no per-round branch, no M[]/K[]/S[] loads. This is the CPU twin of what
// crack.js's JIT does; it's why a specialised kernel beats the general rt_md5.
static void emit_md5_baked(FILE *o, int len)
{
    fprintf(o, "        { unsigned char dg[16]; unsigned int a,b,c,d,ff;\n");
    for (int k = 0; k < 14; k++) {
        char term[200]; term[0] = 0; int any = 0;
        for (int t = 0; t < 4; t++) {
            int pos = 4*k + t, sh = 8*t; char one[64];
            if (pos < len) {
                if (sh) snprintf(one, sizeof one, "((unsigned)buf[%d]<<%d)", pos, sh);
                else    snprintf(one, sizeof one, "(unsigned)buf[%d]", pos);
            } else if (pos == len) {
                if (sh) snprintf(one, sizeof one, "(0x80u<<%d)", sh);
                else    snprintf(one, sizeof one, "0x80u");
            } else continue;
            if (any) strcat(term, " | ");
            strcat(term, one); any = 1;
        }
        fprintf(o, "          unsigned int m%d = %s;\n", k, any ? term : "0");
    }
    fprintf(o, "          unsigned int m14 = %du, m15 = 0u;\n", len * 8);
    fprintf(o, "          a=0x67452301u; b=0xefcdab89u; c=0x98badcfeu; d=0x10325476u;\n");
    for (int i = 0; i < 64; i++) {
        int g = i < 16 ? i : i < 32 ? (5*i+1)&15 : i < 48 ? (3*i+5)&15 : (7*i)&15;
        int s = MD5S[i];
        const char *F = i < 16 ? "((b&c)|(~b&d))" : i < 32 ? "((d&b)|(~d&c))"
                      : i < 48 ? "(b^c^d)" : "(c^(b|~d))";
        fprintf(o, "          ff=(%s)+a+%uu+m%d; a=d; d=c; c=b; b=b+((ff<<%d)|(ff>>%d));\n",
                F, MD5K[i], g, s, 32 - s);
    }
    fprintf(o, "          a+=0x67452301u; b+=0xefcdab89u; c+=0x98badcfeu; d+=0x10325476u;\n");
    fprintf(o, "          dg[0]=(unsigned char)a;dg[1]=(unsigned char)(a>>8);dg[2]=(unsigned char)(a>>16);dg[3]=(unsigned char)(a>>24);\n");
    fprintf(o, "          dg[4]=(unsigned char)b;dg[5]=(unsigned char)(b>>8);dg[6]=(unsigned char)(b>>16);dg[7]=(unsigned char)(b>>24);\n");
    fprintf(o, "          dg[8]=(unsigned char)c;dg[9]=(unsigned char)(c>>8);dg[10]=(unsigned char)(c>>16);dg[11]=(unsigned char)(c>>24);\n");
    fprintf(o, "          dg[12]=(unsigned char)d;dg[13]=(unsigned char)(d>>8);dg[14]=(unsigned char)(d>>16);dg[15]=(unsigned char)(d>>24);\n");
    fprintf(o, "          if (rt_set_has(&TB, (const char *)dg, 16)) {\n"
               "            pthread_mutex_lock(&MX);\n"
               "            for (int h = 0; h < 16; h++) printf(\"%%02x\", dg[h]);\n"
               "            putchar(':'); fwrite(buf, 1, %d, stdout); putchar('\\n');\n"
               "            pthread_mutex_unlock(&MX); n++; } }\n", len);
}

// The per-member sink action, using 'len' as the member length expression (a
// constant when fixed, "p" when variable) and 'lenp1' as length+1 for a write.
static void emit_sink(FILE *o, int dup, int match, int count, int hash,
                      const char *len, const char *lenp1)
{
    if (dup)        fprintf(o, "        rt_dup_add(d, (const char *)buf, %s);\n", len);
    else if (match && hash && const_int(len) >= 0 && const_int(len) <= 55 && !strcmp(HA->name, "md5"))
                    emit_md5_baked(o, const_int(len));   // fixed length -> specialised inline MD5
    else if (match && hash)
                    fprintf(o, "        { unsigned char dg[%d]; %s(buf, %s, dg);\n"
                               "          if (rt_set_has(&TB, (const char *)dg, %d)) {\n"
                               "            pthread_mutex_lock(&MX);\n"
                               "            for (int h = 0; h < %d; h++) printf(\"%%02x\", dg[h]);\n"
                               "            putchar(':'); fwrite(buf, 1, %s, stdout); putchar('\\n');\n"
                               "            pthread_mutex_unlock(&MX); n++; } }\n",
                               HA->dglen, HA->cpu_fn, len, HA->dglen, HA->dglen, len);
    else if (match) fprintf(o, "        if (rt_set_has(&TB, (const char *)buf, %s))"
                               " { pthread_mutex_lock(&MX); fwrite(buf, 1, %s, stdout);"
                               " pthread_mutex_unlock(&MX); n++; }\n", len, lenp1);
    else if (count) fputs("        n++;\n", o);
    else            fprintf(o, "        fwrite(buf, 1, %s, stdout);\n", lenp1);
}

// The run() body for a pattern with a loop repeat X{a,b}. The repeat is one
// super-wheel of the outer odometer: pre wheels are the digits above it, post
// wheels the digits below, exactly the order the interpreter walks an embedded
// repeat ([b-c]{1,2}[x-y] runs bx by cx cy bbx...). Seeding decodes 'from' into
// a segment length rk and the body's digits; the step is a base-(product of the
// body) number that lengthens at a segment boundary. Within a segment every
// position sits at a fixed offset, so the common step delta-patches one byte --
// the fixed path's speed -- and only the rare carry into a longer segment (once
// per 26x of the members, for [a-z]{1,7}) rebuilds the variable-length tail.
static void emit_looprep_body(FILE *o, const struct build *B,
                              int count, int match, int hash, int progress, int acc)
{
    int P = B->lr_at, nw = B->nw, Q = nw - P, m = B->lr_nsw;
    const struct wheel *pre = B->w, *post = B->w + P, *sw = B->lr_sw;
    int a = B->lr_a, b = B->lr_b;

    int preoff[MAXW], PW = 0;
    for (int i = 0; i < P; i++) { preoff[i] = PW; PW += pre[i].L; }
    int soff[REP_SUBW], W = 0;
    for (int j = 0; j < m; j++) { soff[j] = W; W += sw[j].L; }
    int postoff[MAXW];
    for (int i = 0, q = 0; i < Q; i++) { postoff[i] = q; q += post[i].L; }

    // C = members of one body copy; segment k holds C^k, M the whole repeat.
    unsigned long long C = 1;
    for (int j = 0; j < m; j++) C *= (unsigned long long)sw[j].n;
    unsigned long long Cp = 1, M = 0;
    for (int k = 0; k < a; k++) Cp *= C;
    for (int k = a; k <= b; k++) { M += Cp; Cp *= C; }
    if (M == 0) M = 1;   // only reached with from==0 (N over 64 bits); keep %/ safe

    // --- seed from 'from' (post least significant, then the repeat, then pre) ---
    fputs("    unsigned long long f = from;\n", o);
    for (int i = Q - 1; i >= 0; i--)
        fprintf(o, "    int q%d = f %% %d; f /= %d;\n", i, post[i].n, post[i].n);
    fprintf(o, "    unsigned long long r = f %% %lluULL; f /= %lluULL;\n", M, M);
    for (int i = P - 1; i >= 0; i--)
        fprintf(o, "    int i%d = f %% %d; f /= %d;\n", i, pre[i].n, pre[i].n);
    fprintf(o, "    int rd[%d];\n", b * m);
    fprintf(o, "    int rk = %d;\n", a);
    fputs("    { unsigned long long seg = 1;\n", o);
    fprintf(o, "      for (int e = 0; e < %d; e++) seg *= %lluULL;\n", a, C);
    fprintf(o, "      while (rk <= %d) { if (r < seg) break; r -= seg; seg *= %lluULL; rk++; }\n", b, C);
    fputs("      for (int c = rk - 1; c >= 0; c--) {\n", o);
    for (int j = m - 1; j >= 0; j--)
        fprintf(o, "        rd[c*%d + %d] = r %% %d; r /= %d;\n", m, j, sw[j].n, sw[j].n);
    fputs("      }\n    }\n", o);
    if (acc) fputs("    unsigned long long n = 0;\n", o);
    fputs("    unsigned long long done = 0;\n", o);

    // --- lay the whole member ---
    for (int i = 0; i < P; i++) {
        char e[16]; snprintf(e, sizeof e, "i%d", i);
        fputs("    ", o); emit_lay(o, i, preoff[i], pre[i].L, e); fputc('\n', o);
    }
    fprintf(o, "    int p = %d;\n", PW);
    fputs("    for (int c = 0; c < rk; c++) {\n", o);
    for (int j = 0; j < m; j++) {
        if (sw[j].L == 1) fprintf(o, "        buf[p] = S%d[rd[c*%d + %d]]; p += 1;\n", j, m, j);
        else fprintf(o, "        memcpy(buf + p, S%d + rd[c*%d + %d] * %d, %d); p += %d;\n",
                     j, m, j, sw[j].L, sw[j].L, sw[j].L);
    }
    fputs("    }\n", o);
    for (int i = 0; i < Q; i++) {
        int t = P + i;
        if (post[i].L == 1) fprintf(o, "    buf[p] = A%d[q%d]; p += 1;\n", t, i);
        else fprintf(o, "    memcpy(buf + p, A%d + q%d * %d, %d); p += %d;\n",
                     t, i, post[i].L, post[i].L, post[i].L);
    }
    fputs("    buf[p] = '\\n';\n", o);

    // --- the odometer ---
    fputs("    for (;;) {\n", o);
    emit_sink(o, 0, match, count, hash, "p", "p + 1");
    fputs("        if (count && ++done == count) goto L_done;\n", o);
    if (progress) fputs("        if ((done & 0xffff) == 0) __atomic_store_n(prog, done, __ATOMIC_RELAXED);\n", o);

    // post wheels (least significant): the offset rides on rk*W but rk holds here.
    for (int i = Q - 1; i >= 0; i--) {
        int t = P + i, K = PW + postoff[i];
        fprintf(o, "        if (++q%d < %d) { ", i, post[i].n);
        if (post[i].L == 1) fprintf(o, "buf[rk*%d + %d] = A%d[q%d];", W, K, t, i);
        else fprintf(o, "memcpy(buf + (rk*%d + %d), A%d + q%d * %d, %d);", W, K, t, i, post[i].L, post[i].L);
        fprintf(o, " goto L_next; } q%d = 0; ", i);
        if (post[i].L == 1) fprintf(o, "buf[rk*%d + %d] = A%d[0];", W, K, t);
        else fprintf(o, "memcpy(buf + (rk*%d + %d), A%d, %d);", W, K, t, post[i].L);
        fputc('\n', o);
    }

    // the repeat body: a base-C odometer over rk*m digits, delta-patched. When
    // the body is a single wheel (the common [a-z]{1,7}), the least significant
    // copy turns nearly every step, so peel it out of the carry loop -- that
    // hot step is then a lone indexed patch, the fixed path's speed, and the
    // loop runs only on the rare carry.
    if (m == 1) {
        int R = sw[0].n, L = sw[0].L;
        if (a == 0) fputs("        if (rk) {\n", o);   // no last copy to peel at rk==0
        for (int pass = 0; pass < 2; pass++) {   // pass 0: the peeled last copy; 1: the loop body
            const char *ix = pass ? "c" : "rk-1";
            const char *ind = pass ? "            " : "        ";
            if (pass) fputs("        for (int c = rk - 2; c >= 0; c--) {\n", o);
            fprintf(o, "%sif (++rd[%s] < %d) { ", ind, ix, R);
            if (L == 1) fprintf(o, "buf[(%s)*%d + %d] = S0[rd[%s]];", ix, W, PW, ix);
            else fprintf(o, "memcpy(buf + ((%s)*%d + %d), S0 + rd[%s] * %d, %d);", ix, W, PW, ix, L, L);
            fprintf(o, " goto L_next; } rd[%s] = 0; ", ix);
            if (L == 1) fprintf(o, "buf[(%s)*%d + %d] = S0[0];", ix, W, PW);
            else fprintf(o, "memcpy(buf + ((%s)*%d + %d), S0, %d);", ix, W, PW, L);
            fputc('\n', o);
            if (pass) fputs("        }\n", o);
        }
        if (a == 0) fputs("        }\n", o);
    } else {
        fputs("        for (int c = rk - 1; c >= 0; c--) {\n", o);
        for (int j = m - 1; j >= 0; j--) {
            int K = PW + soff[j];
            fprintf(o, "            if (++rd[c*%d + %d] < %d) { ", m, j, sw[j].n);
            if (sw[j].L == 1) fprintf(o, "buf[c*%d + %d] = S%d[rd[c*%d + %d]];", W, K, j, m, j);
            else fprintf(o, "memcpy(buf + (c*%d + %d), S%d + rd[c*%d + %d] * %d, %d);", W, K, j, m, j, sw[j].L, sw[j].L);
            fputs(" goto L_next; }\n", o);
            fprintf(o, "            rd[c*%d + %d] = 0; ", m, j);
            if (sw[j].L == 1) fprintf(o, "buf[c*%d + %d] = S%d[0];", W, K, j);
            else fprintf(o, "memcpy(buf + (c*%d + %d), S%d, %d);", W, K, j, sw[j].L);
            fputc('\n', o);
        }
        fputs("        }\n", o);
    }

    // segment exhausted: grow to the next length, or roll the repeat over and
    // carry into the pre wheels. The tail's width changed, so relay it whole.
    fputs("        rk++;\n", o);
    fprintf(o, "        { int rolled = rk > %d;\n", b);
    fprintf(o, "          if (rolled) rk = %d;\n", a);
    fprintf(o, "          for (int t = 0; t < rk*%d; t++) rd[t] = 0;\n", m);
    fprintf(o, "          p = %d;\n", PW);
    fputs("          for (int c = 0; c < rk; c++) {\n", o);
    for (int j = 0; j < m; j++) {
        if (sw[j].L == 1) fprintf(o, "              buf[p] = S%d[rd[c*%d + %d]]; p += 1;\n", j, m, j);
        else fprintf(o, "              memcpy(buf + p, S%d + rd[c*%d + %d] * %d, %d); p += %d;\n", j, m, j, sw[j].L, sw[j].L, sw[j].L);
    }
    fputs("          }\n", o);
    for (int i = 0; i < Q; i++) {
        int t = P + i;
        if (post[i].L == 1) fprintf(o, "          buf[p] = A%d[q%d]; p += 1;\n", t, i);
        else fprintf(o, "          memcpy(buf + p, A%d + q%d * %d, %d); p += %d;\n", t, i, post[i].L, post[i].L, post[i].L);
    }
    fputs("          buf[p] = '\\n';\n", o);
    fputs("          if (rolled) {\n", o);
    for (int i = P - 1; i >= 0; i--) {
        char e[16]; snprintf(e, sizeof e, "i%d", i);
        fprintf(o, "            if (++i%d < %d) { ", i, pre[i].n);
        emit_lay(o, i, preoff[i], pre[i].L, e);
        fprintf(o, " goto L_next; } i%d = 0; ", i);
        emit_lay(o, i, preoff[i], pre[i].L, "0");
        fputc('\n', o);
    }
    fputs("            goto L_done;\n          }\n        }\n", o);
    fputs("        goto L_next;\n      L_next: ;\n    }\n  L_done:\n", o);
    if (acc) fputs("    *acc += n;\n", o);
}

// A compacting lay of alphabet table A<ai>'s alternative <dv> at buf[p],
// advancing p by its real length -- fixed or variable width. Used by the
// permutation body, where widths vary and the member is rebuilt each step.
static void emit_compact_lay(FILE *o, int ai, const struct wheel *w, const char *dv)
{
    if (w->L == 1)
        fprintf(o, "        buf[p++] = A%d[%s];\n", ai, dv);
    else if (w->L > 1)
        fprintf(o, "        memcpy(buf + p, A%d + %s*%d, %d); p += %d;\n",
                ai, dv, w->L, w->L, w->L);
    else
        fprintf(o, "        { int o = A%do[%s], l = A%dl[%s];"
                   " memcpy(buf + p, A%d + o, l); p += l; }\n", ai, dv, ai, dv, ai);
}

// The run() body for a pattern with an ordered permutation (re){{lo,hi!}}. The
// choice is one super-wheel sitting between the pre wheels (more significant)
// and the post wheels (less significant), exactly the order the interpreter
// walks a quantified group. Its radix is sum_{s=lo}^{hi} P(n,s), decoded in two
// steps: the index r first selects the size block s (the blocks ascending, sizes
// PSZ[s] = P(n,s) baked), then the remainder unranks to s distinct pool indices
// through the factorial number system -- position p takes rank r/block among the
// still-unused members, block = P(n-1-p, s-1-p). That reproduces rxenum -e's
// order exactly. The member is rebuilt each step (its length, the size s, and
// the pool widths all vary), which the hash-bound keycracking sink hides; the
// step is a plain mixed-radix carry, post first.
static void emit_perm_body(FILE *o, const struct build *B,
                           int count, int match, int hash, int progress, int acc)
{
    int P = B->perm_at, nw = B->nw, Q = nw - P, lo = B->perm_lo, hi = B->perm_hi;
    int ord = B->perm_ordered;
    const struct wheel *pre = B->w, *post = B->w + P, *pool = &B->perm_pool;
    int n = pool->n;

    // NPERM = sum_{s=lo}^{hi} of the block; PSZ[s] = the block (P or C) for the
    // size decode.
    unsigned long long NPERM = 0, PSZ[64] = {0};
    for (int s = 0; s <= hi; s++) {
        choose_block(n, s, ord, &PSZ[s]);
        if (s >= lo) NPERM += PSZ[s];
    }

    // --- seed from 'from' (post least significant, then the choice, then pre) ---
    fputs("    unsigned long long f = from;\n", o);
    for (int i = Q - 1; i >= 0; i--)
        fprintf(o, "    int q%d = f %% %d; f /= %d;\n", i, post[i].n, post[i].n);
    fprintf(o, "    unsigned long long r = f %% %lluULL; f /= %lluULL;\n", NPERM, NPERM);
    for (int i = P - 1; i >= 0; i--)
        fprintf(o, "    int i%d = f %% %d; f /= %d;\n", i, pre[i].n, pre[i].n);
    if (acc) fputs("    unsigned long long n = 0;\n", o);
    fputs("    unsigned long long done = 0;\n", o);

    // PSZ[s] = the block for size s, subtracted off to find the size and the
    // within-block rank; only sizes lo..hi are ever selected.
    fprintf(o, "    static const unsigned long long PSZ[%d] = {", hi + 1);
    for (int s = 0; s <= hi; s++) fprintf(o, "%s%lluULL", s ? "," : "", PSZ[s]);
    fputs("};\n", o);
    int K = hi < 1 ? 1 : hi;
    fprintf(o, "    int idx[%d];\n", K);
    if (ord) fprintf(o, "    int used[%d];\n", K);   // the picks so far -- O(k), not O(n)

    fputs("    for (;;) {\n", o);
    // r -> size s and within-block rank rr: subtract each block from lo up.
    fprintf(o, "        int s = %d; unsigned long long rr = r;\n", lo);
    fputs("        for (;;) { unsigned long long blk = PSZ[s]; if (rr < blk) break; rr -= blk; s++; }\n", o);
    if (ord) {
        // Ordered: unrank rr -> idx[0..s) through the factorial number system.
        // Position p takes rank rr/block among the s-p members not yet chosen;
        // the rank becomes an actual index by stepping past the earlier picks at
        // or below it. Only the s picks are tracked (used[], sorted), never the
        // whole pool -- so this is O(k), independent of the pool size n.
        fputs("        { int nused = 0;\n"
              "          for (int p = 0; p < s; p++) {\n"
              "              unsigned long long block = 1;\n", o);
        fprintf(o, "              for (int t = 0; t < s - 1 - p; t++) block *= (unsigned long long)(%d - p - t);\n", n - 1);
        fputs("              unsigned long long rank = rr / block; rr %= block;\n"
              "              int actual = (int)rank;\n"
              "              for (int u = 0; u < nused; u++) if (used[u] <= actual) actual++;\n"
              "              idx[p] = actual;\n"
              "              int ins = nused;\n"
              "              while (ins > 0 && used[ins-1] > actual) { used[ins] = used[ins-1]; ins--; }\n"
              "              used[ins] = actual; nused++;\n"
              "          } }\n", o);
    } else {
        // Unordered: unrank rr -> s ascending indices through the combinatorial
        // number system (colex order) -- for k = s..1 the largest c whose
        // C(c,k) fits the remainder, then recurse below it.
        fprintf(o, "        { unsigned long long jj = rr; int up = %d;\n", n);
        fputs("          for (int k = s; k >= 1; k--) {\n"
              "              int lo2 = k - 1, hi2 = up - 1;\n"
              "              while (lo2 < hi2) { int mid = (lo2 + hi2 + 1) >> 1;\n"
              "                  if (cchoose(mid, k) <= jj) lo2 = mid; else hi2 = mid - 1; }\n"
              "              jj -= cchoose(lo2, k); idx[k-1] = lo2; up = lo2;\n"
              "          } }\n", o);
    }

    // --- lay the member: pre wheels, the s chosen pool members, post wheels ---
    fputs("        int p = 0;\n", o);
    for (int i = 0; i < P; i++) {
        char dv[16]; snprintf(dv, sizeof dv, "i%d", i);
        emit_compact_lay(o, i, &pre[i], dv);
    }
    fputs("        for (int pp = 0; pp < s; pp++) {\n", o);
    if (pool->L == 1)
        fputs("            buf[p++] = PB[idx[pp]];\n", o);
    else if (pool->L > 1)
        fprintf(o, "            memcpy(buf + p, PB + idx[pp]*%d, %d); p += %d;\n",
                pool->L, pool->L, pool->L);
    else
        fputs("            { int o = PO[idx[pp]], l = PL[idx[pp]];"
              " memcpy(buf + p, PB + o, l); p += l; }\n", o);
    fputs("        }\n", o);
    // {{...?}}: quell the last laid item's trailing separator -- back p up over
    // it before the post wheels (so a post odometer follows the chopped item).
    if (B->perm_chop) fprintf(o, "        if (s) p -= %d;\n", B->perm_chop);
    for (int i = 0; i < Q; i++) {
        char dv[16]; snprintf(dv, sizeof dv, "q%d", i);
        emit_compact_lay(o, P + i, &post[i], dv);
    }
    fputs("        buf[p] = '\\n';\n", o);

    emit_sink(o, 0, match, count, hash, "p", "p + 1");
    fputs("        if (count && ++done == count) break;\n", o);
    if (progress) fputs("        if ((done & 0xffff) == 0) __atomic_store_n(prog, done, __ATOMIC_RELAXED);\n", o);

    // --- step: a mixed-radix carry, post (least significant) then r then pre ---
    fputs("        { int carry = 1;\n", o);
    for (int i = Q - 1; i >= 0; i--)
        fprintf(o, "          if (carry) { if (++q%d < %d) carry = 0; else q%d = 0; }\n",
                i, post[i].n, i);
    fprintf(o, "          if (carry) { if (++r < %lluULL) carry = 0; else r = 0; }\n", NPERM);
    for (int i = P - 1; i >= 0; i--)
        fprintf(o, "          if (carry) { if (++i%d < %d) carry = 0; else i%d = 0; }\n",
                i, pre[i].n, i);
    fputs("          if (carry) break; }\n", o);
    fputs("    }\n", o);
    if (acc) fputs("    *acc += n;\n", o);
}

// The generated program. Its core is run(from, count): seed the odometer to
// the member at index 'from' -- the mixed-radix digits of 'from', least
// significant wheel first -- then step it, handing 'count' members to the sink
// (0 = to the end). That shardable shape is the point: a thread, and one day a
// GPU lane, is just a run() over its own slice, so parallelism is built into the
// emitted code, not wrapped around it. Each wheel is a byte at buf[w]; a step
// rewrites only the byte that turned -- the delta render the tree walk cannot
// do -- and the most significant wheel carrying out is the end of the set.
//
// The count sink is the one that threads: it renders and tallies, sharing
// nothing, so main splits [0, N) across a thread each and sums the tallies. N is
// baked in ('nmemb', the member total as a decimal string, or NULL when it
// overflows 64 bits and cannot be split -- then the count runs on one thread).
// The write sink stays one ordered thread: several threads on one stdout would
// interleave, and generation to a pipe is I/O-bound anyway, so there is nothing
// to win there.
static void emit(FILE *o, const char *pattern, const struct build *B,
                 int sink, const char *nmemb, int verbose, int hash, int psec)
{
    struct wheel *w = B->w;
    int nw = B->nw;
    int count    = sink == SINK_COUNT;
    int match    = sink == SINK_MATCH;
    int dup      = sink == SINK_DUP;
    // How the match sink loads its targets: raw plaintext lines, or hex digests
    // decoded to the hash's byte length (keycracking, hash the candidate then
    // probe).
    char loadbuf[64];
    snprintf(loadbuf, sizeof loadbuf, "rt_load_hashes(&TB, argv[1], %d)", HA->dglen);
    const char *load = hash ? loadbuf : "rt_load(&TB, argv[1])";
    int acc      = count || match;              // sinks that tally into *acc
    int threaded = (acc || dup) && nmemb;       // split [0,N) when N fits 64 bits
    int rt       = match || dup;                // needs the embedded runtime
    int progress = psec > 0 && (count || match) && threaded;  // -p live reporter

    // Sizing. A member is rebuilt each step (not delta-patched) when a wheel is
    // variable-width, or a backreference copies a group -- either makes offsets
    // depend on the choice. bufcap is the most a member can hold; multi marks
    // memcpy (and string.h). Backref patterns cost bufcap the copied spans too,
    // so it is walked over the op list rather than the wheels.
    int variable = B->has_backref, multi = B->has_backref;
    for (int i = 0; i < nw; i++)
        if (w[i].L == 0) { variable = 1; multi = 1; }
        else if (w[i].L > 1) multi = 1;
    if (B->lr_active) {            // a loop repeat renders a variable-length tail
        variable = 1;
        for (int j = 0; j < B->lr_nsw; j++) if (B->lr_sw[j].L > 1) multi = 1;
    }
    if (B->perm_active) {          // a permutation is rebuilt from indices each step
        variable = 1;
        if (B->perm_pool.L != 1) multi = 1;
    }

    int wmax[MAXW];                             // each wheel's longest branch
    for (int i = 0; i < nw; i++) {
        if (w[i].L) wmax[i] = w[i].L;
        else { int m = 0; for (int j = 0; j < w[i].n; j++) if (w[i].alen[j] > m) m = w[i].alen[j]; wmax[i] = m; }
    }
    int bufcap = 0;
    {
        int gpos[MAXW], glen[MAXW], p = 0;      // longest-member simulation
        for (int k = 0; k < B->nops; k++) {
            struct op op = B->ops[k];
            if      (op.kind == OP_LAY)   p += wmax[op.arg];
            else if (op.kind == OP_OPEN)  gpos[op.arg] = p;
            else if (op.kind == OP_CLOSE) glen[op.arg] = p - gpos[op.arg];
            else                          p += glen[op.arg];   // OP_COPY
        }
        bufcap = p;
    }
    if (B->lr_active) {           // the op walk misses the repeat's grown copies
        int PW = 0, W = 0, QW = 0;
        for (int i = 0; i < B->lr_at; i++) PW += w[i].L;
        for (int i = B->lr_at; i < nw; i++) QW += w[i].L;
        for (int j = 0; j < B->lr_nsw; j++) W += B->lr_sw[j].L;
        bufcap = PW + B->lr_b * W + QW;
    }
    if (B->perm_active) {         // the pool wheel is out of the op stream too
        int PW = 0, QW = 0, poolmax = 0;
        for (int i = 0; i < B->perm_at; i++) PW += wmax[i];
        for (int i = B->perm_at; i < nw; i++) QW += wmax[i];
        const struct wheel *pool = &B->perm_pool;
        if (pool->L) poolmax = pool->L;
        else for (int j = 0; j < pool->n; j++) if (pool->alen[j] > poolmax) poolmax = pool->alen[j];
        bufcap = PW + B->perm_hi * poolmax + QW;
    }
    int off[MAXW], TL = 0;
    if (!variable) for (int i = 0; i < nw; i++) { off[i] = TL; TL += w[i].L; }

    // Dedup is a closed form for the fixed case: each wheel owns a disjoint slice
    // of the member, so distinct = product of each wheel's distinct alternatives,
    // and the verdict follows without enumerating, at any size. A variable wheel
    // breaks that -- members alias across positions -- so those fall through to
    // the enumerate-and-hash path. Only -d -v enumerates in the fixed case, to
    // show the repeats, and only when the set is small enough.
    if (dup && !variable) {
        mpz_t total, distinct, dups;
        mpz_init_set_ui(total, 1);
        mpz_init_set_ui(distinct, 1);
        for (int i = 0; i < nw; i++) {
            mpz_mul_ui(total, total, (unsigned long)w[i].n);
            mpz_mul_ui(distinct, distinct, (unsigned long)wheel_distinct(&w[i]));
        }
        mpz_init(dups);
        mpz_sub(dups, total, distinct);
        int has = mpz_sgn(dups) > 0;
        int listable = verbose && has && mpz_cmp_ui(total, DUP_LIST_CAP) <= 0;
        if (!listable) {
            fputs("/* generated by rxejit from: ", o);
            emit_comment(o, pattern);
            fputs(" */\n#include <stdio.h>\n\nint main(void)\n{\n", o);
            if (has)
                gmp_fprintf(o, "    printf(\"%Zd members, %Zd distinct, %Zd duplicate%s"
                               " -- NOT distinct\\n\");\n", total, distinct, dups,
                               mpz_cmp_ui(dups, 1) == 0 ? "" : "s");
            else
                gmp_fprintf(o, "    printf(\"%Zd members, all distinct\\n\");\n", total);
            if (verbose && has)
                fputs("    fprintf(stderr, \"rxejit: too many members to list\\n\");\n", o);
            fprintf(o, "    return %d;\n}\n", has ? 1 : 0);
            mpz_clear(total); mpz_clear(distinct); mpz_clear(dups);
            return;
        }
        mpz_clear(total); mpz_clear(distinct); mpz_clear(dups);
        // listable: fall through to the enumerate-and-hash code below.
    }

    fputs("/* generated by rxejit from: ", o);
    emit_comment(o, pattern);
    fputs(" */\n#include <stdio.h>\n", o);
    if (multi && !rt) fputs("#include <string.h>\n", o);      // rt sinks get it via the runtime
    // match keeps a mutex for the rare hit print even on one thread, so pthread
    // comes in for it too; count and dup need pthread only when they thread.
    if (threaded || match) fputs("#include <stdlib.h>\n#include <pthread.h>\n#include <unistd.h>\n", o);
    if (progress) fputs("#include <time.h>\n", o);
    fputc('\n', o);

    if (rt) fputs(RXEJIT_RT, o), fputc('\n', o);
    if (match) {
        fputs("static struct rt_set TB;   /* the targets, read-only once loaded */\n", o);
        fputs("static pthread_mutex_t MX = PTHREAD_MUTEX_INITIALIZER;\n\n", o);
    }
    // C(c,k) for the combinatorial-number-system unrank of an unordered choice.
    // __int128 keeps the partial products exact and unwrapped; the result fits.
    if (B->perm_active && !B->perm_ordered)
        fputs("static unsigned long long cchoose(int c, int k) {\n"
              "    if (k < 0 || k > c) return 0;\n"
              "    if (k > c - k) k = c - k;\n"
              "    unsigned __int128 r = 1;\n"
              "    for (int i = 0; i < k; i++) r = r * (unsigned)(c - i) / (unsigned)(i + 1);\n"
              "    return (unsigned long long)r;\n}\n\n", o);

    fputs(dup
        ? "static void run(unsigned long long from, unsigned long long count, struct rt_dup *d)\n{\n"
        : acc && progress
        ? "static void run(unsigned long long from, unsigned long long count, unsigned long long *acc, unsigned long long *prog)\n{\n"
        : acc
        ? "static void run(unsigned long long from, unsigned long long count, unsigned long long *acc)\n{\n"
        : "static void run(unsigned long long from, unsigned long long count)\n{\n", o);

    // Alphabet tables: each wheel's bytes, plus offset/length tables for a
    // variable wheel, whose branches are not evenly spaced.
    for (int i = 0; i < nw; i++) {
        int bytes = w[i].L ? w[i].n * w[i].L
                           : w[i].aoff[w[i].n - 1] + w[i].alen[w[i].n - 1];
        fprintf(o, "    static const unsigned char A%d[] = {", i);
        if (bytes == 0) fputs("0", o);              // all-empty branches; never read
        for (int j = 0; j < bytes; j++)
            fprintf(o, "%s%d", j ? "," : "", (unsigned char)w[i].base[j]);
        fputs("};\n", o);
        if (w[i].L == 0) {
            fprintf(o, "    static const int A%do[] = {", i);
            for (int j = 0; j < w[i].n; j++) fprintf(o, "%s%d", j ? "," : "", w[i].aoff[j]);
            fputs("};\n", o);
            fprintf(o, "    static const int A%dl[] = {", i);
            for (int j = 0; j < w[i].n; j++) fprintf(o, "%s%d", j ? "," : "", w[i].alen[j]);
            fputs("};\n", o);
        }
    }
    // The loop repeat's body sub-wheels get their own tables (all fixed width).
    for (int j = 0; B->lr_active && j < B->lr_nsw; j++) {
        const struct wheel *s = &B->lr_sw[j];
        fprintf(o, "    static const unsigned char S%d[] = {", j);
        for (int k = 0; k < s->n * s->L; k++)
            fprintf(o, "%s%d", k ? "," : "", (unsigned char)s->base[k]);
        fputs("};\n", o);
    }
    // The permutation's pool is its own table (PB), with offset/length tables
    // (PO/PL) when its members are uneven -- an item is looked up by index.
    if (B->perm_active) {
        const struct wheel *pool = &B->perm_pool;
        int bytes = pool->L ? pool->n * pool->L
                            : pool->aoff[pool->n - 1] + pool->alen[pool->n - 1];
        fputs("    static const unsigned char PB[] = {", o);
        if (bytes == 0) fputs("0", o);
        for (int j = 0; j < bytes; j++) fprintf(o, "%s%d", j ? "," : "", (unsigned char)pool->base[j]);
        fputs("};\n", o);
        if (pool->L == 0) {
            fputs("    static const int PO[] = {", o);
            for (int j = 0; j < pool->n; j++) fprintf(o, "%s%d", j ? "," : "", pool->aoff[j]);
            fputs("};\n", o);
            fputs("    static const int PL[] = {", o);
            for (int j = 0; j < pool->n; j++) fprintf(o, "%s%d", j ? "," : "", pool->alen[j]);
            fputs("};\n", o);
        }
    }

    fprintf(o, "    unsigned char buf[%d];\n", bufcap + 1);

    if (B->lr_active) {
        emit_looprep_body(o, B, count, match, hash, progress, acc);
        fputs("}\n\n", o);
        goto after_run;
    }
    if (B->perm_active) {
        emit_perm_body(o, B, count, match, hash, progress, acc);
        fputs("}\n\n", o);
        goto after_run;
    }

    // Seed each wheel from 'from': digit = from %% radix, then from /= radix,
    // walking from the least significant wheel up, so the walk starts at 'from'.
    fputs("    unsigned long long f = from;\n", o);
    for (int i = nw - 1; i >= 0; i--)
        fprintf(o, "    int i%d = f %% %d; f /= %d;\n", i, w[i].n, w[i].n);
    if (acc) fputs("    unsigned long long n = 0;\n", o);
    fputs("    unsigned long long done = 0;\n", o);

    if (!variable) {
        // Fixed width: lay the member once, then a loop whose step delta-patches
        // only the byte(s) that turned. The length is a compile-time constant.
        char len[16], lenp1[16];
        snprintf(len, sizeof len, "%d", TL);
        snprintf(lenp1, sizeof lenp1, "%d", TL + 1);
        fprintf(o, "    buf[%d] = '\\n';\n", TL);
        for (int i = 0; i < nw; i++) {
            char e[16]; snprintf(e, sizeof e, "i%d", i);
            fputs("    ", o); emit_lay(o, i, off[i], w[i].L, e); fputc('\n', o);
        }
        fputs("    for (;;) {\n", o);
        emit_sink(o, dup, match, count, hash, len, lenp1);
        fputs("        if (count && ++done == count) break;\n", o);
        if (progress) fputs("        if ((done & 0xffff) == 0) __atomic_store_n(prog, done, __ATOMIC_RELAXED);\n", o);
        for (int i = nw - 1; i >= 0; i--) {
            char e[16]; snprintf(e, sizeof e, "i%d", i);
            fprintf(o, "        if (++i%d < %d) { ", i, w[i].n);
            emit_lay(o, i, off[i], w[i].L, e);
            fprintf(o, " continue; } i%d = 0; ", i);
            emit_lay(o, i, off[i], w[i].L, "0");
            fputc('\n', o);
        }
        fputs("        break;\n    }\n", o);
        if (acc) fputs("    *acc += n;\n", o);
    } else {
        // Variable width: a goto-threaded odometer. Each wheel keeps its current
        // byte position; the step jumps to the relay for the wheel that turned,
        // which rebuilds only the suffix from there. Since the least significant
        // wheel turns nearly every step, most members re-lay just a byte or two,
        // recovering the delta speed the fixed path has while still handling a
        // member whose width the choice decides. The relay blocks fall through,
        // so each wheel's lay is emitted once (the code is O(wheels), not O(n^2)).
        for (int i = 0; i < nw; i++) fprintf(o, "    int pos%d = 0;\n", i);
        for (int g = 0; g < B->ngroup; g++)
            fprintf(o, "    int g%d_pos = 0, g%d_len = 0;\n", g, g);
        fputs("    int p = 0;\n"
              "    goto R_init;\n"
              "  R_emit:\n"
              "    buf[p] = '\\n';\n", o);
        emit_sink(o, dup, match, count, hash, "p", "p + 1");
        fputs("    if (count && ++done == count) goto R_done;\n", o);
        if (progress) fputs("    if ((done & 0xffff) == 0) __atomic_store_n(prog, done, __ATOMIC_RELAXED);\n", o);
        for (int i = nw - 1; i >= 0; i--)
            fprintf(o, "    if (++i%d < %d) { p = pos%d; goto R_%d; } i%d = 0;\n",
                    i, w[i].n, i, i, i);
        fputs("    goto R_done;\n  R_init:\n", o);
        for (int k = 0; k < B->nops; k++) {
            struct op op = B->ops[k];
            int i = op.arg;
            if (op.kind == OP_LAY) {
                if (w[i].L)
                    fprintf(o, "  R_%d: pos%d = p; memcpy(buf + p, A%d + i%d * %d, %d); p += %d;\n",
                            i, i, i, i, w[i].L, w[i].L, w[i].L);
                else
                    fprintf(o, "  R_%d: pos%d = p; memcpy(buf + p, A%d + A%do[i%d], A%dl[i%d]);"
                               " p += A%dl[i%d];\n", i, i, i, i, i, i, i, i, i);
            } else if (op.kind == OP_OPEN) {
                fprintf(o, "        g%d_pos = p;\n", i);
            } else if (op.kind == OP_CLOSE) {
                fprintf(o, "        g%d_len = p - g%d_pos;\n", i, i);
            } else {  // OP_COPY
                fprintf(o, "        memcpy(buf + p, buf + g%d_pos, g%d_len); p += g%d_len;\n",
                        i, i, i);
            }
        }
        fputs("    goto R_emit;\n  R_done:\n", o);
        if (acc) fputs("    *acc += n;\n", o);
        fputs("    return;\n", o);
    }
    fputs("}\n\n", o);

after_run:
    if (dup) {
        // Each thread dedups its shard into its own set; main merges them and
        // reads the verdict off the total. Same asymmetry rxedup reports:
        // distinct is exact, a duplicate conclusive, out-of-memory inconclusive.
        fputs("static int report(struct rt_dup *d)\n{\n"
              "    unsigned long long total = d->total, distinct = d->used, dups = total - distinct;\n"
              "    if (d->oom) { printf(\"%llu members, all distinct so far, then out of memory -- inconclusive\\n\", total); return 2; }\n"
              "    if (dups) {\n"
              "        printf(\"%llu members, %llu distinct, %llu duplicate%s -- NOT distinct\\n\", total, distinct, dups, dups == 1 ? \"\" : \"s\");\n", o);
        if (verbose)
            fputs("        for (unsigned long i = 0; i < d->cap; i++)\n"
                  "            if (d->slot[i].key && d->slot[i].mult > 1)\n"
                  "                printf(\"  %llu x %.*s\\n\", d->slot[i].mult, (int)d->slot[i].len, d->slot[i].key);\n", o);
        fputs("        return 1;\n    }\n"
              "    printf(\"%llu members, all distinct\\n\", total);\n"
              "    return 0;\n}\n\n", o);

        if (threaded) {
            fprintf(o, "#define NMEMB %sULL\n#define MAXT  256\n\n", nmemb);
            fputs("struct shard { unsigned long long from, count; struct rt_dup dup; };\n\n"
                  "static void *worker(void *p)\n{\n"
                  "    struct shard *s = p;\n"
                  "    if (!rt_dup_init(&s->dup)) s->dup.oom = 1;\n"
                  "    run(s->from, s->count, &s->dup);\n"
                  "    return 0;\n"
                  "}\n\n"
                  "int main(int argc, char **argv)\n{\n"
                  "    long np = sysconf(_SC_NPROCESSORS_ONLN);\n"
                  "    int T = np < 1 ? 1 : (int)np;\n"
                  "    if (argc > 1) { int j = atoi(argv[1]); if (j > 0) T = j; }\n"
                  "    if (T > MAXT) T = MAXT;\n"
                  "    unsigned long long N = NMEMB;\n"
                  "    if (N == 0) { printf(\"0 members, all distinct\\n\"); return 0; }\n"
                  "    if (N < (unsigned long long)T) T = (int)N;\n"
                  "    struct shard sh[MAXT];\n"
                  "    pthread_t   tid[MAXT];\n"
                  "    unsigned long long base = N / (unsigned long long)T,\n"
                  "                       rem  = N % (unsigned long long)T, off = 0;\n"
                  "    for (int t = 0; t < T; t++) {\n"
                  "        sh[t].from = off;\n"
                  "        sh[t].count = base + ((unsigned long long)t < rem ? 1 : 0);\n"
                  "        off += sh[t].count;\n"
                  "    }\n"
                  "    for (int t = 1; t < T; t++) pthread_create(&tid[t], 0, worker, &sh[t]);\n"
                  "    worker(&sh[0]);\n"
                  "    for (int t = 1; t < T; t++) pthread_join(tid[t], 0);\n"
                  "    for (int t = 1; t < T; t++) rt_dup_absorb(&sh[0].dup, &sh[t].dup);\n"
                  "    int ret = report(&sh[0].dup);\n"
                  "    for (int t = 0; t < T; t++) rt_dup_free(&sh[t].dup);\n"
                  "    return ret;\n}\n", o);
        } else {
            fputs("int main(void)\n{\n"
                  "    struct rt_dup d;\n"
                  "    if (!rt_dup_init(&d)) { fprintf(stderr, \"rxejit: out of memory\\n\"); return 3; }\n"
                  "    run(0, 0, &d);\n"
                  "    int ret = report(&d);\n"
                  "    rt_dup_free(&d);\n"
                  "    return ret;\n}\n", o);
        }
    } else if (threaded) {
        // A thread per shard of [0, N). Count and match share the whole split;
        // only the setup (match loads the targets first, taking its jobs arg one
        // later) and the report (match to stderr, and it frees the set) differ.
        fprintf(o, "#define NMEMB %sULL\n#define MAXT  256\n", nmemb);
        if (progress) fprintf(o, "#define PSEC  %d\n", psec);
        fputc('\n', o);
        fputs(progress
            ? "struct shard { unsigned long long from, count, total, done; };\n\n"
            : "struct shard { unsigned long long from, count, total; };\n\n", o);
        fputs("static void *worker(void *p)\n{\n"
              "    struct shard *s = p;\n"
              "    s->total = 0;\n", o);
        fputs(progress
            ? "    s->done = 0;\n    run(s->from, s->count, &s->total, &s->done);\n"
            : "    run(s->from, s->count, &s->total);\n", o);
        fputs("    return 0;\n}\n\n", o);
        if (progress)
            // A monitor thread every PSEC seconds: sum the shards' progress (a
            // relaxed atomic, so no lock and no torn read TSan complains of),
            // and print percent / rate / elapsed / eta. Cancelled at the join so
            // a short run does not wait out a sleep.
            fputs("static struct shard *SH; static int NT;\n"
                  "static unsigned long long NALL; static int RUNNING = 1;\n"
                  "static double T0;\n"
                  "static double rt_now(void) { struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts); return ts.tv_sec + ts.tv_nsec / 1e9; }\n"
                  "static void *monitor(void *u)\n{\n"
                  "    (void)u;\n"
                  "    while (__atomic_load_n(&RUNNING, __ATOMIC_RELAXED)) {\n"
                  "        sleep(PSEC);\n"
                  "        if (!__atomic_load_n(&RUNNING, __ATOMIC_RELAXED)) break;\n"
                  "        unsigned long long d = 0;\n"
                  "        for (int t = 0; t < NT; t++) d += __atomic_load_n(&SH[t].done, __ATOMIC_RELAXED);\n"
                  "        double el = rt_now() - T0;\n"
                  "        double fr = NALL ? (double)d / (double)NALL : 0;\n"
                  "        double rate = el > 0 ? d / el : 0;\n"
                  "        double eta = fr > 0 ? el * (1 - fr) / fr : 0;\n"
                  "        fprintf(stderr, \"progress: %5.1f%%  %llu/%llu  %.3g/s  elapsed %.0fs  eta %.0fs\\n\",\n"
                  "                fr * 100, d, NALL, rate, el, eta);\n"
                  "    }\n"
                  "    return 0;\n}\n\n", o);
        fputs("int main(int argc, char **argv)\n{\n", o);
        if (match) {
            fputs("    if (argc < 2) { fprintf(stderr, \"usage: %s TARGETFILE [jobs]\\n\", argv[0]); return 2; }\n", o);
            fprintf(o, "    if (%s) { fprintf(stderr, \"rxejit: cannot read %%s\\n\", argv[1]); return 2; }\n", load);
            fputs("    int argoff = 2;\n", o);
        } else
            fputs("    int argoff = 1;\n", o);
        fputs("    long np = sysconf(_SC_NPROCESSORS_ONLN);\n"
              "    int T = np < 1 ? 1 : (int)np;\n"
              "    if (argc > argoff) { int j = atoi(argv[argoff]); if (j > 0) T = j; }\n"
              "    if (T > MAXT) T = MAXT;\n"
              "    unsigned long long N = NMEMB;\n", o);
        fputs(match
              ? "    if (N == 0) { fprintf(stderr, \"0 matches\\n\"); rt_set_free(&TB); return 0; }\n"
              : "    if (N == 0) { printf(\"0\\n\"); return 0; }\n", o);
        fputs("    if (N < (unsigned long long)T) T = (int)N;\n"
              "    struct shard sh[MAXT];\n"
              "    pthread_t   tid[MAXT];\n"
              "    unsigned long long base = N / (unsigned long long)T,\n"
              "                       rem  = N % (unsigned long long)T, off = 0;\n"
              "    for (int t = 0; t < T; t++) {\n"
              "        sh[t].from = off;\n"
              "        sh[t].count = base + ((unsigned long long)t < rem ? 1 : 0);\n", o);
        if (progress) fputs("        sh[t].done = 0;\n", o);
        fputs("        off += sh[t].count;\n"
              "    }\n", o);
        if (progress)
            fputs("    SH = sh; NT = T; NALL = N; T0 = rt_now();\n"
                  "    pthread_t montid; pthread_create(&montid, 0, monitor, 0);\n", o);
        fputs("    for (int t = 1; t < T; t++) pthread_create(&tid[t], 0, worker, &sh[t]);\n"
              "    worker(&sh[0]);\n"
              "    for (int t = 1; t < T; t++) pthread_join(tid[t], 0);\n", o);
        if (progress)
            fputs("    __atomic_store_n(&RUNNING, 0, __ATOMIC_RELAXED); pthread_cancel(montid); pthread_join(montid, 0);\n", o);
        fputs("    unsigned long long total = 0;\n"
              "    for (int t = 0; t < T; t++) total += sh[t].total;\n", o);
        fputs(match
              ? "    fprintf(stderr, \"%llu matches\\n\", total);\n    rt_set_free(&TB);\n"
              : "    printf(\"%llu\\n\", total);\n", o);
        fputs("    return 0;\n}\n", o);
    } else if (match) {
        // N over 64 bits: unsplittable, so one thread (the mutex uncontended).
        fputs("int main(int argc, char **argv)\n{\n"
              "    if (argc < 2) { fprintf(stderr, \"usage: %s TARGETFILE\\n\", argv[0]); return 2; }\n", o);
        fprintf(o, "    if (%s) { fprintf(stderr, \"rxejit: cannot read %%s\\n\", argv[1]); return 2; }\n", load);
        fputs("    unsigned long long acc = 0;\n"
              "    run(0, 0, &acc);\n"
              "    fprintf(stderr, \"%llu matches\\n\", acc);\n"
              "    rt_set_free(&TB);\n"
              "    return 0;\n}\n", o);
    } else if (count) {
        fputs("int main(void)\n{\n"
              "    unsigned long long acc = 0;\n"
              "    run(0, 0, &acc);\n"
              "    printf(\"%llu\\n\", acc);\n"
              "    return 0;\n}\n", o);
    } else {
        fputs("int main(void)\n{\n    run(0, 0);\n    return 0;\n}\n", o);
    }
}

// Emit a string s as a C string literal, escaped and broken across lines, so a
// block of generated source can be handed to clBuildProgram at runtime.
static void emit_c_string(FILE *o, const char *s)
{
    fputc('"', o);
    for (; *s; s++) {
        if      (*s == '\\') fputs("\\\\", o);
        else if (*s == '"')  fputs("\\\"", o);
        else if (*s == '\n') fputs("\\n\"\n\"", o);
        else                 fputc(*s, o);
    }
    fputc('"', o);
}

// The -G hybrid backend for a bare variable-count repeat X{a,b} ([a-z]{1,8}).
// The CPU owns the high wheels, the GPU a fixed block of low ones. For each
// member length k the CPU sweeps the high (k - GW) wheels, handing the GPU an
// opaque prefix (bytes, already laid); the GPU brute-forces GW low wheels,
// prepends the prefix, hashes, and keeps the rare hit. The kernel never knows
// what produced the prefix -- so the same engine will drive an arbitrary
// structure once a producer other than this odometer feeds it (the path to
// backrefs/alternations on the GPU). A kernel is built per member length via
// -D, so its width and MD5 length are compile-time constants -- the fixed
// path's speed, no runtime k. GW is picked so the low sweep is a fat batch
// (>= ~4M lanes); RXEJIT_GW overrides it for testing the prefix path on small
// masks. Hits are plaintext (length varies by length), re-hashed on the host.
static void emit_gpu_hybrid(FILE *o, const char *pattern, const struct build *B, int psec)
{
    const struct wheel *sw = &B->lr_sw[0];
    int R = sw->n, L = sw->L, a = B->lr_a, b = B->lr_b;
    int maxw = b * L;

    // GW: the low wheels the GPU sweeps. Smallest g whose R^g clears ~4M lanes,
    // capped at b; the env var forces it, to exercise the prefix path on a small
    // mask where the adaptive choice would put the whole thing on the GPU.
    long long gpow = 1; int gt = b;
    for (int g = 1; g <= b; g++) { gpow *= R; if (gpow >= (1 << 22)) { gt = g; break; } }
    const char *ge = getenv("RXEJIT_GW");
    if (ge) { int v = atoi(ge); if (v >= 1 && v <= b) gt = v; }

    char *ksrc = NULL; size_t ksz = 0;
    FILE *ms = open_memstream(&ksrc, &ksz);
    fputs(RXEJIT_CL, ms);
    fprintf(ms, "__constant uchar A0[] = {");
    for (int j = 0; j < R * L; j++) fprintf(ms, "%s%d", j ? "," : "", (unsigned char)sw->base[j]);
    fputs("};\n", ms);
    // T (total bytes), PLEN (prefix bytes), GW (low wheels) come in per length
    // via -D; R, L, MAXW, MAXHITS are the same for every length, baked here.
    fprintf(ms,
        "__kernel void crackL(ulong lo_base, ulong lo_N, __global const uchar *pfx,\n"
        "                     __global const uchar *tgt, uint ntgt,\n"
        "                     __global uint *hlen, __global uchar *hbuf, volatile __global uint *nhits)\n{\n"
        "    ulong j = lo_base + (ulong)get_global_id(0);\n    if (j >= lo_N) return;\n"
        "    uchar buf[T];\n"
        "    for (int i = 0; i < PLEN; i++) buf[i] = pfx[i];\n"
        "    ulong f = j;\n"
        "    for (int c = GW - 1; c >= 0; c--) { uint d = f %% %d; f /= %d;\n", R, R);
    if (L == 1) fputs("        buf[PLEN + c] = A0[d];\n", ms);
    else for (int t = 0; t < L; t++) fprintf(ms, "        buf[PLEN + c*%d + %d] = A0[d*%d + %d];\n", L, t, L, t);
    fprintf(ms,
        "    }\n    uchar dg[%d]; %s(buf, T, dg);\n"
        "    if (cl_tgt_has(tgt, ntgt, dg)) { uint s = atomic_inc(nhits);\n"
        "        if (s < %d) { hlen[s] = T; for (int t = 0; t < T; t++) hbuf[s*%d + t] = buf[t]; } }\n"
        "}\n", HA->dglen, HA->gpu_fn, 1 << 20, maxw);
    fclose(ms);

    fputs("/* generated by rxejit -G (hybrid) from: ", o);
    emit_comment(o, pattern);
    fputs(" */\n#define CL_TARGET_OPENCL_VERSION 300\n"
          "#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n#include <time.h>\n#include <CL/cl.h>\n\n", o);
    fprintf(o, "#define PSEC %d\n", psec);
    fputs("static double rt_now(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec+t.tv_nsec/1e9;}\n", o);
    fputs(RXEJIT_RT, o); fputc('\n', o);

    fputs("static const char *KSRC =\n", o);
    emit_c_string(o, ksrc);
    fputs(";\n\n", o);
    free(ksrc);

    fprintf(o, "#define MAXW %d\n#define MAXHITS (1<<20)\n#define R %dULL\n#define L %d\n"
               "#define AMIN %d\n#define BMAX %d\n#define GT %d\n#define DG %d\n#define HASHFN %s\n\n",
            maxw, R, L, a, b, gt, HA->dglen, HA->cpu_fn);
    fprintf(o, "static const unsigned char A0h[] = {");
    for (int j = 0; j < R * L; j++) fprintf(o, "%s%d", j ? "," : "", (unsigned char)sw->base[j]);
    fputs("};\n\n", o);

    fputs("static int cmpdg(const void *a, const void *b) { return memcmp(a, b, DG); }\n"
          "static unsigned char *load_targets(const char *path, unsigned *ntgt)\n{\n"
          "    FILE *fp = fopen(path, \"r\");\n    if (!fp) return NULL;\n"
          "    unsigned cap = 1024, n = 0;\n    unsigned char *t = malloc((size_t)cap * DG);\n"
          "    char line[256];\n"
          "    while (fgets(line, sizeof line, fp)) {\n"
          "        int ok = 1; unsigned char d[DG];\n"
          "        for (int i = 0; i < DG; i++) { unsigned v;\n"
          "            if (sscanf(line + i*2, \"%2x\", &v) != 1) { ok = 0; break; } d[i] = (unsigned char)v; }\n"
          "        if (!ok) continue;\n"
          "        if (n == cap) { cap *= 2; t = realloc(t, (size_t)cap * DG); }\n"
          "        memcpy(t + (size_t)n * DG, d, DG); n++;\n"
          "    }\n    fclose(fp);\n    qsort(t, n, DG, cmpdg);\n    *ntgt = n;\n    return t;\n}\n\n", o);

    fputs("#define CK(call) do { cl_int e_ = (call); if (e_ != CL_SUCCESS) {\\\n"
          "    fprintf(stderr, \"rxejit -G: %s failed (%d)\\n\", #call, e_); return 2; } } while (0)\n\n", o);

    fputs("#if PSEC\n"
          "#define DRAIN(EV, NN) do {\\\n"
          "    cl_ulong s0_ = 0, s1_ = 0;\\\n"
          "    clGetEventProfilingInfo(EV, CL_PROFILING_COMMAND_START, sizeof s0_, &s0_, NULL);\\\n"
          "    clGetEventProfilingInfo(EV, CL_PROFILING_COMMAND_END, sizeof s1_, &s1_, NULL);\\\n"
          "    gpu_ns += s1_ - s0_; done += (NN);\\\n"
          "    double now_ = rt_now();\\\n"
          "    if (now_ - tlast >= PSEC) { double el_ = now_ - t0, fr_ = NALL ? (double)done / NALL : 0;\\\n"
          "        fprintf(stderr, \"gpu: %5.1f%%  %llu/%llu  %.3g/s  eta %.0fs  busy %.0f%%\\n\",\\\n"
          "                fr_ * 100, done, (unsigned long long)NALL, el_ > 0 ? done / el_ : 0,\\\n"
          "                fr_ > 0 ? el_ * (1 - fr_) / fr_ : 0, el_ > 0 ? (gpu_ns / 1e9) / el_ * 100 : 0);\\\n"
          "        tlast = now_; }\\\n"
          "} while (0)\n"
          "#else\n"
          "#define DRAIN(EV, NN) ((void)(EV), (void)(NN))\n"
          "#endif\n\n", o);

    fputs("int main(int argc, char **argv)\n{\n"
          "    if (argc < 2) { fprintf(stderr, \"usage: %s TARGETFILE\\n\", argv[0]); return 2; }\n"
          "    unsigned ntgt = 0;\n    unsigned char *tgt = load_targets(argv[1], &ntgt);\n"
          "    if (!tgt) { fprintf(stderr, \"rxejit -G: cannot read %s\\n\", argv[1]); return 2; }\n"
          "    if (ntgt == 0) { fprintf(stderr, \"0 matches\\n\"); return 0; }\n\n"
          "    cl_platform_id plat; cl_device_id dev; cl_int e;\n"
          "    if (clGetPlatformIDs(1, &plat, NULL) != CL_SUCCESS) { fprintf(stderr, \"rxejit -G: no OpenCL platform\\n\"); return 2; }\n"
          "    if (clGetDeviceIDs(plat, CL_DEVICE_TYPE_GPU, 1, &dev, NULL) != CL_SUCCESS) { fprintf(stderr, \"rxejit -G: no OpenCL GPU\\n\"); return 2; }\n"
          "    cl_context ctx = clCreateContext(NULL, 1, &dev, NULL, NULL, &e); CK(e);\n"
          "#if PSEC\n"
          "    cl_queue_properties qp[] = { CL_QUEUE_PROPERTIES, CL_QUEUE_PROFILING_ENABLE, 0 };\n"
          "    cl_command_queue q = clCreateCommandQueueWithProperties(ctx, dev, qp, &e); CK(e);\n"
          "#else\n"
          "    cl_command_queue q = clCreateCommandQueueWithProperties(ctx, dev, NULL, &e); CK(e);\n"
          "#endif\n\n"
          "    /* One program+kernel per member length k, its width and MD5 length baked. */\n"
          "    cl_kernel kern[BMAX + 1] = {0};\n"
          "    for (int k = AMIN; k <= BMAX; k++) {\n"
          "        int gw = k < GT ? k : GT, plen = (k - gw) * L, t = k * L;\n"
          "        const char *uo = getenv(\"RXEJIT_NO_UNROLL\") ? \" -D RXEJIT_UNROLL=0\" : \"\";\n"
          "        char opts[128]; snprintf(opts, sizeof opts, \"-D T=%d -D PLEN=%d -D GW=%d -D DGLEN=%d%s\", t, plen, gw, DG, uo);\n"
          "        cl_program pr = clCreateProgramWithSource(ctx, 1, &KSRC, NULL, &e); CK(e);\n"
          "        if (clBuildProgram(pr, 1, &dev, opts, NULL, NULL) != CL_SUCCESS) {\n"
          "            size_t ls = 0; clGetProgramBuildInfo(pr, dev, CL_PROGRAM_BUILD_LOG, 0, NULL, &ls);\n"
          "            char *log = malloc(ls + 1); clGetProgramBuildInfo(pr, dev, CL_PROGRAM_BUILD_LOG, ls, log, NULL); log[ls] = 0;\n"
          "            fprintf(stderr, \"rxejit -G: build (k=%d) failed:\\n%s\\n\", k, log); return 2; }\n"
          "        kern[k] = clCreateKernel(pr, \"crackL\", &e); CK(e);\n"
          "    }\n\n"
          "    cl_mem mt = clCreateBuffer(ctx, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, (size_t)ntgt * DG, tgt, &e); CK(e);\n"
          "    cl_uint *hlen = calloc(MAXHITS, sizeof *hlen);\n    unsigned char *hbuf = calloc((size_t)MAXHITS, MAXW);\n"
          "    cl_uint nhits = 0;\n"
          "    cl_mem mhl = clCreateBuffer(ctx, CL_MEM_WRITE_ONLY, (size_t)MAXHITS * sizeof(cl_uint), NULL, &e); CK(e);\n"
          "    cl_mem mhb = clCreateBuffer(ctx, CL_MEM_WRITE_ONLY, (size_t)MAXHITS * MAXW, NULL, &e); CK(e);\n"
          "    cl_mem mn = clCreateBuffer(ctx, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, sizeof nhits, &nhits, &e); CK(e);\n"
          "    cl_mem mpfx = clCreateBuffer(ctx, CL_MEM_READ_ONLY, MAXW, NULL, &e); CK(e);\n"
          "    for (int k = AMIN; k <= BMAX; k++) {\n"
          "        CK(clSetKernelArg(kern[k], 2, sizeof mpfx, &mpfx));\n"
          "        CK(clSetKernelArg(kern[k], 3, sizeof mt, &mt));\n"
          "        CK(clSetKernelArg(kern[k], 4, sizeof ntgt, &ntgt));\n"
          "        CK(clSetKernelArg(kern[k], 5, sizeof mhl, &mhl));\n"
          "        CK(clSetKernelArg(kern[k], 6, sizeof mhb, &mhb));\n"
          "        CK(clSetKernelArg(kern[k], 7, sizeof mn, &mn));\n"
          "    }\n\n"
          "    cl_ulong TILE = 1ULL << 24;\n"
          "#if PSEC\n"
          "    /* Progress and GPU occupancy: candidates done vs the total, and the\n"
          "       fraction of wall time the device was actually executing a kernel\n"
          "       (from event profiling) -- a busy well under 100%% means the pipeline\n"
          "       is starving between launches. */\n"
          "    unsigned long long NALL = 0;\n"
          "    for (int k = AMIN; k <= BMAX; k++) { unsigned long long rk = 1; for (int i = 0; i < k; i++) rk *= R; NALL += rk; }\n"
          "    double t0 = rt_now(), tlast = t0; unsigned long long done = 0, gpu_ns = 0;\n"
          "#endif\n"
          "    for (int k = AMIN; k <= BMAX; k++) {\n"
          "        int gw = k < GT ? k : GT, hi = k - gw, plen = hi * L;\n"
          "        cl_ulong loN = 1; for (int i = 0; i < gw; i++) loN *= R;\n"
          "        cl_ulong npfx = 1; for (int i = 0; i < hi; i++) npfx *= R;\n"
          "        CK(clSetKernelArg(kern[k], 1, sizeof loN, &loN));\n"
          "        for (cl_ulong pi = 0; pi < npfx; pi++) {\n"
          "            unsigned char pbuf[MAXW]; cl_ulong pf = pi;\n"
          "            for (int hp = hi - 1; hp >= 0; hp--) { unsigned dd = pf % R; pf /= R;\n"
          "                for (int t = 0; t < L; t++) pbuf[hp*L + t] = A0h[dd*L + t]; }\n"
          "            if (plen) CK(clEnqueueWriteBuffer(q, mpfx, CL_TRUE, 0, plen, pbuf, 0, NULL, NULL));\n"
          "            cl_event prev = NULL; cl_ulong prev_n = 0;\n"
          "            for (cl_ulong base = 0; base < loN; base += TILE) {\n"
          "                cl_ulong n = (loN - base < TILE) ? (loN - base) : TILE;\n"
          "                size_t global = (size_t)((n + 255) / 256) * 256;\n"
          "                CK(clSetKernelArg(kern[k], 0, sizeof base, &base));\n"
          "                cl_event ev;\n"
          "                CK(clEnqueueNDRangeKernel(q, kern[k], 1, NULL, &global, NULL, 0, NULL, &ev));\n"
          "                if (prev) { CK(clWaitForEvents(1, &prev)); DRAIN(prev, prev_n); clReleaseEvent(prev); }\n"
          "                prev = ev; prev_n = n;\n"
          "            }\n"
          "            if (prev) { CK(clWaitForEvents(1, &prev)); DRAIN(prev, prev_n); clReleaseEvent(prev); }\n"
          "        }\n"
          "    }\n"
          "    CK(clEnqueueReadBuffer(q, mn, CL_TRUE, 0, sizeof nhits, &nhits, 0, NULL, NULL));\n"
          "    unsigned got = nhits < MAXHITS ? nhits : MAXHITS;\n"
          "    CK(clEnqueueReadBuffer(q, mhl, CL_TRUE, 0, (size_t)got * sizeof(cl_uint), hlen, 0, NULL, NULL));\n"
          "    CK(clEnqueueReadBuffer(q, mhb, CL_TRUE, 0, (size_t)got * MAXW, hbuf, 0, NULL, NULL));\n\n"
          "    for (unsigned i = 0; i < got; i++) {\n"
          "        unsigned char *p = hbuf + (size_t)i * MAXW, dg[DG];\n"
          "        HASHFN(p, hlen[i], dg);\n"
          "        for (int h = 0; h < DG; h++) printf(\"%02x\", dg[h]);\n"
          "        putchar(':'); fwrite(p, 1, hlen[i], stdout); putchar('\\n');\n"
          "    }\n"
          "    if (nhits > MAXHITS) fprintf(stderr, \"rxejit -G: %u hits, only %u recorded\\n\", nhits, MAXHITS);\n"
          "    fprintf(stderr, \"%u matches\\n\", nhits);\n"
          "    free(tgt); free(hlen); free(hbuf);\n    return 0;\n}\n", o);
}

// A compacting lay into a device kernel: alternative <dv> of table <tb> (with
// offset/length tables <to>/<tl> when the wheel is variable width) is copied to
// buf[p], p advanced by its real length. The pool and every pre/post wheel of a
// permutation kernel lay this way, since widths vary and the member is built
// left to right.
static void emit_cl_lay(FILE *ms, const struct wheel *w, const char *tb,
                        const char *to, const char *tl, const char *dv)
{
    if (w->L == 1)
        fprintf(ms, "    buf[p++] = %s[%s];\n", tb, dv);
    else if (w->L > 1)
        fprintf(ms, "    for (int t = 0; t < %d; t++) buf[p++] = %s[%s*%d + t];\n", w->L, tb, dv, w->L);
    else
        fprintf(ms, "    { int o = %s[%s], l = %s[%s]; for (int t = 0; t < l; t++) buf[p++] = %s[o + t]; }\n",
                to, dv, tl, dv, tb);
}

// Emit one wheel's __constant tables into the kernel: the bytes A<i>, and for a
// variable wheel the per-alternative offset/length A<i>o / A<i>l.
static void emit_cl_wheel_tables(FILE *ms, const struct wheel *w, int i)
{
    int bytes = w->L ? w->n * w->L : w->aoff[w->n - 1] + w->alen[w->n - 1];
    fprintf(ms, "__constant uchar A%d[] = {", i);
    if (bytes == 0) fputs("0", ms);
    for (int j = 0; j < bytes; j++) fprintf(ms, "%s%d", j ? "," : "", (unsigned char)w->base[j]);
    fputs("};\n", ms);
    if (w->L == 0) {
        fprintf(ms, "__constant int A%do[] = {", i);
        for (int j = 0; j < w->n; j++) fprintf(ms, "%s%d", j ? "," : "", w->aoff[j]);
        fputs("};\n", ms);
        fprintf(ms, "__constant int A%dl[] = {", i);
        for (int j = 0; j < w->n; j++) fprintf(ms, "%s%d", j ? "," : "", w->alen[j]);
        fputs("};\n", ms);
    }
}

// The -G combinatorial-choice backend for (re){{lo,hi!}} / {{lo,hi}} (with
// fixed/variable pre and post wheels). Producer-free like the hybrid: one grid
// over the whole space, each lane unranking its global index into a candidate.
// The index decodes to the pre/post wheel digits and the choice index r; r
// selects the size s (the blocks ascending) and unranks to s pool members --
// factorial number system for a permutation, combinatorial for a combination,
// exactly as the CPU body does -- so a lane's candidate is the CPU's at that
// index and the hit sets agree. Both unranks track only the s picks (O(k),
// independent of the pool size), so nothing pool-wide lives in a lane's private
// memory. The candidate must fit one hash block; its width is baked (MAXW).
// Hits are re-hashed on the host.
static void emit_gpu_perm(FILE *o, const char *pattern, const struct build *B,
                          const char *nmemb, int psec)
{
    int P = B->perm_at, nw = B->nw, lo = B->perm_lo, hi = B->perm_hi, ord = B->perm_ordered;
    const struct wheel *pool = &B->perm_pool;
    int n = pool->n;

    unsigned long long NPERM = 0, PSZ[64] = {0};
    for (int s = 0; s <= hi; s++) {
        choose_block(n, s, ord, &PSZ[s]);
        if (s >= lo) NPERM += PSZ[s];
    }

    int poolmax = pool->L ? pool->L : 0;
    if (!pool->L) for (int j = 0; j < n; j++) if (pool->alen[j] > poolmax) poolmax = pool->alen[j];
    int maxw = hi * poolmax;
    for (int i = 0; i < nw; i++) {
        int wm = B->w[i].L;
        if (wm == 0) for (int j = 0; j < B->w[i].n; j++) if (B->w[i].alen[j] > wm) wm = B->w[i].alen[j];
        maxw += wm;
    }
    if (maxw < 1) maxw = 1;

    char *ksrc = NULL; size_t ksz = 0;
    FILE *ms = open_memstream(&ksrc, &ksz);
    fputs(RXEJIT_CL, ms);
    fprintf(ms, "#define MAXW %d\n#define MAXHITS %d\n#define NPERM %lluULL\n"
                "#define NP %d\n#define LO %d\n", maxw, 1 << 20, NPERM, n, lo);
    for (int i = 0; i < nw; i++) emit_cl_wheel_tables(ms, &B->w[i], i);
    fputs("__constant ulong PSZ[] = {", ms);
    for (int s = 0; s <= hi; s++) fprintf(ms, "%s%lluUL", s ? "," : "", PSZ[s]);
    fputs("};\n", ms);
    // The pool tables (PB, and PO/PL when uneven) and, for a combination, the
    // Pascal table BINOM[c*HI1+k] = C(c,k), come in as __global kernel arguments,
    // not __constant arrays -- a large dictionary pool overflows __constant, and
    // these are touched only when laying a candidate, not in the hash inner loop.
    // (BINOM saturates past 64 bits; it is only compared against a remainder that
    // fits, so "too big" reads correctly as "greater".)
    if (!ord) fprintf(ms, "#define HI1 %d\n", hi + 1);

    fputs("__kernel void crackP(ulong base, ulong NALL,\n"
          "                     __global const uchar *tgt, uint ntgt,\n"
          "                     __global uint *hlen, __global uchar *hbuf, volatile __global uint *nhits,\n"
          "                     __global const uchar *PB", ms);
    if (pool->L == 0) fputs(", __global const int *PO, __global const int *PL", ms);
    if (!ord)         fputs(", __global const ulong *BINOM", ms);
    fputs(")\n{\n"
          "    ulong j = base + (ulong)get_global_id(0);\n    if (j >= NALL) return;\n"
          "    uchar buf[MAXW];\n    ulong f = j;\n", ms);
    // decode digits: post (nw-1..P) least significant, then r, then pre (P-1..0)
    for (int i = nw - 1; i >= P; i--)
        fprintf(ms, "    uint d%d = f %% %d; f /= %d;\n", i, B->w[i].n, B->w[i].n);
    fputs("    ulong r = f % NPERM; f /= NPERM;\n", ms);
    for (int i = P - 1; i >= 0; i--)
        fprintf(ms, "    uint d%d = f %% %d; f /= %d;\n", i, B->w[i].n, B->w[i].n);
    fputs("    int p = 0;\n", ms);
    // lay pre wheels
    for (int i = 0; i < P; i++) {
        char dv[16], to[24], tl[24], tb[16];
        snprintf(dv, sizeof dv, "d%d", i);
        snprintf(to, sizeof to, "A%do", i); snprintf(tl, sizeof tl, "A%dl", i);
        snprintf(tb, sizeof tb, "A%d", i);
        emit_cl_lay(ms, &B->w[i], tb, to, tl, dv);
    }
    // the choice: size decode, unrank into idx[0..s), then lay each chosen member
    fputs("    int s = LO; ulong rr = r;\n"
          "    for (;;) { ulong blk = PSZ[s]; if (rr < blk) break; rr -= blk; s++; }\n", ms);
    fprintf(ms, "    int idx[%d];\n", hi < 1 ? 1 : hi);
    if (ord)
        // Factorial number system, tracking only the s picks (used[], sorted),
        // never the whole pool -- O(k), independent of the pool size NP, so no
        // NP-wide private array to spill. Rank -> actual index by stepping past
        // the earlier picks at or below it.
        fprintf(ms, "    { int used[%d]; int nused = 0;\n"
              "      for (int pp = 0; pp < s; pp++) {\n"
              "          ulong block = 1;\n"
              "          for (int t = 0; t < s - 1 - pp; t++) block *= (ulong)(NP - 1 - pp - t);\n"
              "          ulong rank = rr / block; rr %%= block;\n"
              "          int actual = (int)rank;\n"
              "          for (int u = 0; u < nused; u++) if (used[u] <= actual) actual++;\n"
              "          idx[pp] = actual;\n"
              "          int ins = nused;\n"
              "          while (ins > 0 && used[ins-1] > actual) { used[ins] = used[ins-1]; ins--; }\n"
              "          used[ins] = actual; nused++;\n"
              "      } }\n", hi < 1 ? 1 : hi);
    else
        fputs("    { ulong jj = rr; int up = NP;\n"
              "      for (int k = s; k >= 1; k--) {\n"
              "          int lo2 = k - 1, hi2 = up - 1;\n"
              "          while (lo2 < hi2) { int mid = (lo2 + hi2 + 1) >> 1;\n"
              "              if (BINOM[mid*HI1 + k] <= jj) lo2 = mid; else hi2 = mid - 1; }\n"
              "          jj -= BINOM[lo2*HI1 + k]; idx[k-1] = lo2; up = lo2;\n"
              "      } }\n", ms);
    fputs("    for (int pp = 0; pp < s; pp++) { int it = idx[pp];\n", ms);
    if (pool->L == 1)
        fputs("        buf[p++] = PB[it];\n", ms);
    else if (pool->L > 1)
        fprintf(ms, "        for (int t = 0; t < %d; t++) buf[p++] = PB[it*%d + t];\n", pool->L, pool->L);
    else
        fputs("        { int o = PO[it], l = PL[it]; for (int t = 0; t < l; t++) buf[p++] = PB[o + t]; }\n", ms);
    fputs("    }\n", ms);
    // {{...?}}: quell the last item's trailing separator before the post wheels.
    if (B->perm_chop) fprintf(ms, "    if (s) p -= %d;\n", B->perm_chop);
    // lay post wheels
    for (int i = P; i < nw; i++) {
        char dv[16], to[24], tl[24], tb[16];
        snprintf(dv, sizeof dv, "d%d", i);
        snprintf(to, sizeof to, "A%do", i); snprintf(tl, sizeof tl, "A%dl", i);
        snprintf(tb, sizeof tb, "A%d", i);
        emit_cl_lay(ms, &B->w[i], tb, to, tl, dv);
    }
    fprintf(ms,
        "    uchar dg[%d]; %s(buf, p, dg);\n"
        "    if (cl_tgt_has(tgt, ntgt, dg)) { uint hs = atomic_inc(nhits);\n"
        "        if (hs < MAXHITS) { hlen[hs] = p; for (int t = 0; t < p; t++) hbuf[hs*MAXW + t] = buf[t]; } }\n"
        "}\n", HA->dglen, HA->gpu_fn);
    fclose(ms);

    fputs("/* generated by rxejit -G (permutation) from: ", o);
    emit_comment(o, pattern);
    fputs(" */\n#define CL_TARGET_OPENCL_VERSION 300\n"
          "#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n#include <time.h>\n#include <CL/cl.h>\n\n", o);
    fprintf(o, "#define PSEC %d\n", psec);
    fputs("static double rt_now(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec+t.tv_nsec/1e9;}\n", o);
    fputs(RXEJIT_RT, o); fputc('\n', o);

    fputs("static const char *KSRC =\n", o);
    emit_c_string(o, ksrc);
    fputs(";\n\n", o);
    free(ksrc);

    fprintf(o, "#define MAXW %d\n#define MAXHITS (1<<20)\n#define NALL %sULL\n#define DG %d\n#define HASHFN %s\n\n",
            maxw, nmemb ? nmemb : "0", HA->dglen, HA->cpu_fn);

    // The pool tables, uploaded to the device as __global buffers so a large
    // dictionary is not bounded by __constant capacity.
    {
        int bytes = pool->L ? pool->n * pool->L : pool->aoff[n - 1] + pool->alen[n - 1];
        fputs("static const unsigned char PBh[] = {", o);
        if (bytes == 0) fputs("0", o);
        for (int j = 0; j < bytes; j++) fprintf(o, "%s%d", j ? "," : "", (unsigned char)pool->base[j]);
        fputs("};\n", o);
        if (pool->L == 0) {
            fputs("static const int POh[] = {", o);
            for (int j = 0; j < n; j++) fprintf(o, "%s%d", j ? "," : "", pool->aoff[j]);
            fputs("};\n", o);
            fputs("static const int PLh[] = {", o);
            for (int j = 0; j < n; j++) fprintf(o, "%s%d", j ? "," : "", pool->alen[j]);
            fputs("};\n", o);
        }
    }
    if (!ord) {
        fputs("static const unsigned long long BINOMh[] = {", o);
        for (int c = 0; c <= n; c++)
            for (int k = 0; k <= hi; k++) {
                unsigned long long v;
                if (choose_block(c, k, 0, &v)) v = ~0ULL;   // > 2^64 -> saturate
                fprintf(o, "%s%lluULL", (c || k) ? "," : "", v);
            }
        fputs("};\n", o);
    }
    fputc('\n', o);

    fputs("static int cmpdg(const void *a, const void *b) { return memcmp(a, b, DG); }\n"
          "static unsigned char *load_targets(const char *path, unsigned *ntgt)\n{\n"
          "    FILE *fp = fopen(path, \"r\");\n    if (!fp) return NULL;\n"
          "    unsigned cap = 1024, n = 0;\n    unsigned char *t = malloc((size_t)cap * DG);\n"
          "    char line[256];\n"
          "    while (fgets(line, sizeof line, fp)) {\n"
          "        int ok = 1; unsigned char d[DG];\n"
          "        for (int i = 0; i < DG; i++) { unsigned v;\n"
          "            if (sscanf(line + i*2, \"%2x\", &v) != 1) { ok = 0; break; } d[i] = (unsigned char)v; }\n"
          "        if (!ok) continue;\n"
          "        if (n == cap) { cap *= 2; t = realloc(t, (size_t)cap * DG); }\n"
          "        memcpy(t + (size_t)n * DG, d, DG); n++;\n"
          "    }\n    fclose(fp);\n    qsort(t, n, DG, cmpdg);\n    *ntgt = n;\n    return t;\n}\n\n", o);

    fputs("#define CK(call) do { cl_int e_ = (call); if (e_ != CL_SUCCESS) {\\\n"
          "    fprintf(stderr, \"rxejit -G: %s failed (%d)\\n\", #call, e_); return 2; } } while (0)\n\n", o);

    fputs("#if PSEC\n"
          "#define DRAIN(EV, NN) do {\\\n"
          "    cl_ulong s0_ = 0, s1_ = 0;\\\n"
          "    clGetEventProfilingInfo(EV, CL_PROFILING_COMMAND_START, sizeof s0_, &s0_, NULL);\\\n"
          "    clGetEventProfilingInfo(EV, CL_PROFILING_COMMAND_END, sizeof s1_, &s1_, NULL);\\\n"
          "    gpu_ns += s1_ - s0_; done += (NN);\\\n"
          "    double now_ = rt_now();\\\n"
          "    if (now_ - tlast >= PSEC) { double el_ = now_ - t0, fr_ = NALL ? (double)done / NALL : 0;\\\n"
          "        fprintf(stderr, \"gpu: %5.1f%%  %llu/%llu  %.3g/s  eta %.0fs  busy %.0f%%\\n\",\\\n"
          "                fr_ * 100, done, (unsigned long long)NALL, el_ > 0 ? done / el_ : 0,\\\n"
          "                fr_ > 0 ? el_ * (1 - fr_) / fr_ : 0, el_ > 0 ? (gpu_ns / 1e9) / el_ * 100 : 0);\\\n"
          "        tlast = now_; }\\\n"
          "} while (0)\n"
          "#else\n"
          "#define DRAIN(EV, NN) ((void)(EV), (void)(NN))\n"
          "#endif\n\n", o);

    fputs("int main(int argc, char **argv)\n{\n"
          "    if (argc < 2) { fprintf(stderr, \"usage: %s TARGETFILE\\n\", argv[0]); return 2; }\n"
          "    unsigned ntgt = 0;\n    unsigned char *tgt = load_targets(argv[1], &ntgt);\n"
          "    if (!tgt) { fprintf(stderr, \"rxejit -G: cannot read %s\\n\", argv[1]); return 2; }\n"
          "    if (ntgt == 0) { fprintf(stderr, \"0 matches\\n\"); return 0; }\n\n"
          "    cl_platform_id plat; cl_device_id dev; cl_int e;\n"
          "    if (clGetPlatformIDs(1, &plat, NULL) != CL_SUCCESS) { fprintf(stderr, \"rxejit -G: no OpenCL platform\\n\"); return 2; }\n"
          "    if (clGetDeviceIDs(plat, CL_DEVICE_TYPE_GPU, 1, &dev, NULL) != CL_SUCCESS) { fprintf(stderr, \"rxejit -G: no OpenCL GPU\\n\"); return 2; }\n"
          "    cl_context ctx = clCreateContext(NULL, 1, &dev, NULL, NULL, &e); CK(e);\n"
          "#if PSEC\n"
          "    cl_queue_properties qp[] = { CL_QUEUE_PROPERTIES, CL_QUEUE_PROFILING_ENABLE, 0 };\n"
          "    cl_command_queue q = clCreateCommandQueueWithProperties(ctx, dev, qp, &e); CK(e);\n"
          "#else\n"
          "    cl_command_queue q = clCreateCommandQueueWithProperties(ctx, dev, NULL, &e); CK(e);\n"
          "#endif\n\n"
          "    const char *uo = getenv(\"RXEJIT_NO_UNROLL\") ? \" -D RXEJIT_UNROLL=0\" : \"\";\n"
          "    char opts[64]; snprintf(opts, sizeof opts, \"-D DGLEN=%d%s\", DG, uo);\n"
          "    cl_program pr = clCreateProgramWithSource(ctx, 1, &KSRC, NULL, &e); CK(e);\n"
          "    if (clBuildProgram(pr, 1, &dev, opts, NULL, NULL) != CL_SUCCESS) {\n"
          "        size_t ls = 0; clGetProgramBuildInfo(pr, dev, CL_PROGRAM_BUILD_LOG, 0, NULL, &ls);\n"
          "        char *log = malloc(ls + 1); clGetProgramBuildInfo(pr, dev, CL_PROGRAM_BUILD_LOG, ls, log, NULL); log[ls] = 0;\n"
          "        fprintf(stderr, \"rxejit -G: build failed:\\n%s\\n\", log); return 2; }\n"
          "    cl_kernel k = clCreateKernel(pr, \"crackP\", &e); CK(e);\n\n"
          "    cl_mem mt = clCreateBuffer(ctx, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, (size_t)ntgt * DG, tgt, &e); CK(e);\n"
          "    cl_uint *hlen = calloc(MAXHITS, sizeof *hlen);\n    unsigned char *hbuf = calloc((size_t)MAXHITS, MAXW);\n"
          "    cl_uint nhits = 0;\n"
          "    cl_mem mhl = clCreateBuffer(ctx, CL_MEM_WRITE_ONLY, (size_t)MAXHITS * sizeof(cl_uint), NULL, &e); CK(e);\n"
          "    cl_mem mhb = clCreateBuffer(ctx, CL_MEM_WRITE_ONLY, (size_t)MAXHITS * MAXW, NULL, &e); CK(e);\n"
          "    cl_mem mn = clCreateBuffer(ctx, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, sizeof nhits, &nhits, &e); CK(e);\n"
          "    cl_mem mpb = clCreateBuffer(ctx, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof PBh, (void *)PBh, &e); CK(e);\n"
          "    cl_ulong NA = NALL;\n"
          "    CK(clSetKernelArg(k, 1, sizeof NA, &NA));\n"
          "    CK(clSetKernelArg(k, 2, sizeof mt, &mt));\n"
          "    CK(clSetKernelArg(k, 3, sizeof ntgt, &ntgt));\n"
          "    CK(clSetKernelArg(k, 4, sizeof mhl, &mhl));\n"
          "    CK(clSetKernelArg(k, 5, sizeof mhb, &mhb));\n"
          "    CK(clSetKernelArg(k, 6, sizeof mn, &mn));\n"
          "    CK(clSetKernelArg(k, 7, sizeof mpb, &mpb));\n", o);
    {
        int ai = 8;
        if (pool->L == 0) {
            fprintf(o,
                "    cl_mem mpo = clCreateBuffer(ctx, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof POh, (void *)POh, &e); CK(e);\n"
                "    cl_mem mpl = clCreateBuffer(ctx, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof PLh, (void *)PLh, &e); CK(e);\n"
                "    CK(clSetKernelArg(k, %d, sizeof mpo, &mpo));\n"
                "    CK(clSetKernelArg(k, %d, sizeof mpl, &mpl));\n", ai, ai + 1);
            ai += 2;
        }
        if (!ord)
            fprintf(o,
                "    cl_mem mbn = clCreateBuffer(ctx, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof BINOMh, (void *)BINOMh, &e); CK(e);\n"
                "    CK(clSetKernelArg(k, %d, sizeof mbn, &mbn));\n", ai);
    }
    fputs("    cl_ulong TILE = 1ULL << 24;\n"
          "#if PSEC\n"
          "    double t0 = rt_now(), tlast = t0; unsigned long long done = 0, gpu_ns = 0;\n"
          "#endif\n"
          "    /* Double-buffered tiles over the whole space, so the GPU never idles\n"
          "       on the host between launches -- at most two tiles in flight. */\n"
          "    cl_event prev = NULL; cl_ulong prev_n = 0;\n"
          "    for (cl_ulong base = 0; base < NA; base += TILE) {\n"
          "        cl_ulong nn = (NA - base < TILE) ? (NA - base) : TILE;\n"
          "        size_t global = (size_t)((nn + 255) / 256) * 256;\n"
          "        CK(clSetKernelArg(k, 0, sizeof base, &base));\n"
          "        cl_event ev;\n"
          "        CK(clEnqueueNDRangeKernel(q, k, 1, NULL, &global, NULL, 0, NULL, &ev));\n"
          "        if (prev) { CK(clWaitForEvents(1, &prev)); DRAIN(prev, prev_n); clReleaseEvent(prev); }\n"
          "        prev = ev; prev_n = nn;\n"
          "    }\n"
          "    if (prev) { CK(clWaitForEvents(1, &prev)); DRAIN(prev, prev_n); clReleaseEvent(prev); }\n"
          "    CK(clEnqueueReadBuffer(q, mn, CL_TRUE, 0, sizeof nhits, &nhits, 0, NULL, NULL));\n"
          "    unsigned got = nhits < MAXHITS ? nhits : MAXHITS;\n"
          "    CK(clEnqueueReadBuffer(q, mhl, CL_TRUE, 0, (size_t)got * sizeof(cl_uint), hlen, 0, NULL, NULL));\n"
          "    CK(clEnqueueReadBuffer(q, mhb, CL_TRUE, 0, (size_t)got * MAXW, hbuf, 0, NULL, NULL));\n\n"
          "    for (unsigned i = 0; i < got; i++) {\n"
          "        unsigned char *p = hbuf + (size_t)i * MAXW, dg[DG];\n"
          "        HASHFN(p, hlen[i], dg);\n"
          "        for (int h = 0; h < DG; h++) printf(\"%02x\", dg[h]);\n"
          "        putchar(':'); fwrite(p, 1, hlen[i], stdout); putchar('\\n');\n"
          "    }\n"
          "    if (nhits > MAXHITS) fprintf(stderr, \"rxejit -G: %u hits, only %u recorded\\n\", nhits, MAXHITS);\n"
          "    fprintf(stderr, \"%u matches\\n\", nhits);\n"
          "    free(tgt); free(hlen); free(hbuf);\n    return 0;\n}\n", o);
}

// The -G generic backend: any finite pattern whose tail is a run of independent
// fixed classes. rxejit (which has the enumerator) is the producer -- it
// stride-seeks the pattern and writes each high prefix to a file; this generated
// consumer is the GPU half. For each prefix it sweeps the fixed low block (G
// distinct wheels), prepends the prefix, hashes, keeps the hit. The head can be
// anything rxe enumerates -- uneven alternations, dictionaries, head-side
// backrefs -- so -G reaches far past a plain mask. A kernel is built per total
// member length on demand (its width and MD5 length baked), so every sweep runs
// at the fixed path's speed. Hits are plaintext, re-hashed on the host.
// The widest member in bytes -- backref copies included, walked over the op list
// the way emit()'s bufcap is. The generic path needs it for the buffer cap and
// the plaintext hit-row stride, since a head backref lays bytes no wheel counts.
static int gpu_maxwidth(const struct build *B)
{
    int wmax[MAXW];
    for (int i = 0; i < B->nw; i++) {
        if (B->w[i].L) wmax[i] = B->w[i].L;
        else { int m = 0; for (int j = 0; j < B->w[i].n; j++) if (B->w[i].alen[j] > m) m = B->w[i].alen[j]; wmax[i] = m; }
    }
    int gpos[MAXW], glen[MAXW], p = 0;
    for (int k = 0; k < B->nops; k++) {
        struct op op = B->ops[k];
        if      (op.kind == OP_LAY)   p += wmax[op.arg];
        else if (op.kind == OP_OPEN)  gpos[op.arg] = p;
        else if (op.kind == OP_CLOSE) glen[op.arg] = p - gpos[op.arg];
        else                          p += glen[op.arg];      // OP_COPY
    }
    return p;
}

static void emit_gpu_generic(FILE *o, const char *pattern, const struct build *B, int G,
                             int lowvar, const char *nmemb, int psec)
{
    // lowvar: the low block holds a variable-width wheel (a dictionary or uneven
    // alternation) with no fixed tail to split on, so the whole pattern is the
    // block (G == nw, empty prefix) and the kernel lays each alternative's real
    // bytes -- compacting as it goes, from the wheel's own offset/length tables
    // -- then hashes the running length. One MD5 block covers any length < 56, so
    // only the byte-copy diverges, not the compression. The fixed low block keeps
    // the straight-line baked path.
    int nw = B->nw;
    struct wheel *lw = B->w + (nw - G);          // the G low wheels (the tail)
    int lwoff[64], lowwidth = 0;
    for (int g = 0; g < G; g++) { lwoff[g] = lowwidth; lowwidth += lw[g].L; }
    unsigned long long lon = 1;
    for (int g = 0; g < G; g++) lon *= (unsigned long long)lw[g].n;
    int maxw = gpu_maxwidth(B);
    if (maxw < 1) maxw = 1;

    char *ksrc = NULL; size_t ksz = 0;
    FILE *ms = open_memstream(&ksrc, &ksz);
    fputs(RXEJIT_CL, ms);
    for (int g = 0; g < G; g++) {
        int bytes = lw[g].L ? lw[g].n * lw[g].L : lw[g].aoff[lw[g].n - 1] + lw[g].alen[lw[g].n - 1];
        fprintf(ms, "__constant uchar A%d[] = {", g);
        if (bytes == 0) fputs("0", ms);
        for (int j = 0; j < bytes; j++) fprintf(ms, "%s%d", j ? "," : "", (unsigned char)lw[g].base[j]);
        fputs("};\n", ms);
        if (lw[g].L == 0) {                       // a variable wheel: offset/length per alternative
            fprintf(ms, "__constant int A%do[] = {", g);
            for (int j = 0; j < lw[g].n; j++) fprintf(ms, "%s%d", j ? "," : "", lw[g].aoff[j]);
            fputs("};\n", ms);
            fprintf(ms, "__constant int A%dl[] = {", g);
            for (int j = 0; j < lw[g].n; j++) fprintf(ms, "%s%d", j ? "," : "", lw[g].alen[j]);
            fputs("};\n", ms);
        }
    }
    fputs("__kernel void crackG(ulong lo_base, ulong lo_N, __global const uchar *pfx,\n"
          "                     __global const uchar *tgt, uint ntgt,\n"
          "                     __global uint *hlen, __global uchar *hbuf, volatile __global uint *nhits)\n{\n"
          "    ulong j = lo_base + (ulong)get_global_id(0);\n    if (j >= lo_N) return;\n", ms);
    if (lowvar) fprintf(ms, "    uchar buf[%d];\n", maxw + 1);
    else        fputs("    uchar buf[T];\n", ms);
    fputs("    for (int i = 0; i < PLEN; i++) buf[i] = pfx[i];\n    ulong f = j;\n", ms);
    for (int g = G - 1; g >= 0; g--) fprintf(ms, "    uint d%d = f %% %d; f /= %d;\n", g, lw[g].n, lw[g].n);
    if (lowvar) {
        // compacting lay: advance p by each alternative's real length
        fputs("    int p = PLEN;\n", ms);
        for (int g = 0; g < G; g++) {
            if (lw[g].L == 1) fprintf(ms, "    buf[p++] = A%d[d%d];\n", g, g);
            else if (lw[g].L > 1) for (int t = 0; t < lw[g].L; t++)
                fprintf(ms, "    buf[p++] = A%d[d%d*%d + %d];\n", g, g, lw[g].L, t);
            else fprintf(ms, "    { int o = A%do[d%d], l = A%dl[d%d]; for (int t = 0; t < l; t++) buf[p++] = A%d[o + t]; }\n",
                         g, g, g, g, g);
        }
        fprintf(ms,
            "    uchar dg[%d]; %s(buf, p, dg);\n"
            "    if (cl_tgt_has(tgt, ntgt, dg)) { uint s = atomic_inc(nhits);\n"
            "        if (s < %d) { hlen[s] = p; for (int t = 0; t < p; t++) hbuf[s*%d + t] = buf[t]; } }\n"
            "}\n", HA->dglen, HA->gpu_fn, 1 << 20, maxw);
    } else {
        for (int g = 0; g < G; g++) {
            if (lw[g].L == 1) fprintf(ms, "    buf[PLEN + %d] = A%d[d%d];\n", lwoff[g], g, g);
            else for (int t = 0; t < lw[g].L; t++)
                fprintf(ms, "    buf[PLEN + %d] = A%d[d%d*%d + %d];\n", lwoff[g] + t, g, g, lw[g].L, t);
        }
        fprintf(ms,
            "    uchar dg[%d]; %s(buf, T, dg);\n"
            "    if (cl_tgt_has(tgt, ntgt, dg)) { uint s = atomic_inc(nhits);\n"
            "        if (s < %d) { hlen[s] = T; for (int t = 0; t < T; t++) hbuf[s*%d + t] = buf[t]; } }\n"
            "}\n", HA->dglen, HA->gpu_fn, 1 << 20, maxw);
    }
    fclose(ms);

    fputs("/* generated by rxejit -G (generic) from: ", o);
    emit_comment(o, pattern);
    fputs(" */\n#define CL_TARGET_OPENCL_VERSION 300\n"
          "#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n#include <time.h>\n#include <CL/cl.h>\n\n", o);
    fprintf(o, "#define PSEC %d\n", psec);
    fputs("static double rt_now(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec+t.tv_nsec/1e9;}\n", o);
    fputs(RXEJIT_RT, o); fputc('\n', o);

    fputs("static const char *KSRC =\n", o);
    emit_c_string(o, ksrc);
    fputs(";\n\n", o);
    free(ksrc);

    // NALL = the grand total, when it fits 64 bits, so -p can show percent/ETA.
    // The consumer streams prefixes and cannot sum it, so rxejit bakes it in.
    fprintf(o, "#define NALL %sULL\n", nmemb ? nmemb : "0");
    fprintf(o, "#define MAXW %d\n#define MAXHITS (1<<20)\n#define LOWWIDTH %d\n#define LON %lluULL\n"
               "#define DG %d\n#define HASHFN %s\n",
            maxw, lowwidth, lon, HA->dglen, HA->cpu_fn);
    fprintf(o, "#define KEY %s\n\n", lowvar ? "plen" : "(plen + LOWWIDTH)");

    fputs("static int cmpdg(const void *a, const void *b) { return memcmp(a, b, DG); }\n"
          "static unsigned char *load_targets(const char *path, unsigned *ntgt)\n{\n"
          "    FILE *fp = fopen(path, \"r\");\n    if (!fp) return NULL;\n"
          "    unsigned cap = 1024, n = 0;\n    unsigned char *t = malloc((size_t)cap * DG);\n"
          "    char line[256];\n"
          "    while (fgets(line, sizeof line, fp)) {\n"
          "        int ok = 1; unsigned char d[DG];\n"
          "        for (int i = 0; i < DG; i++) { unsigned v;\n"
          "            if (sscanf(line + i*2, \"%2x\", &v) != 1) { ok = 0; break; } d[i] = (unsigned char)v; }\n"
          "        if (!ok) continue;\n"
          "        if (n == cap) { cap *= 2; t = realloc(t, (size_t)cap * DG); }\n"
          "        memcpy(t + (size_t)n * DG, d, DG); n++;\n"
          "    }\n    fclose(fp);\n    qsort(t, n, DG, cmpdg);\n    *ntgt = n;\n    return t;\n}\n\n", o);

    fputs("#define CK(call) do { cl_int e_ = (call); if (e_ != CL_SUCCESS) {\\\n"
          "    fprintf(stderr, \"rxejit -G: %s failed (%d)\\n\", #call, e_); return 2; } } while (0)\n\n", o);

    // A completed tile: under -p, fold its device runtime into the busy total and
    // its count into the progress, printing every PSEC seconds; otherwise nothing.
    fputs("#if PSEC\n"
          "#define DRAIN(EV, NN) do {\\\n"
          "    cl_ulong s0_ = 0, s1_ = 0;\\\n"
          "    clGetEventProfilingInfo(EV, CL_PROFILING_COMMAND_START, sizeof s0_, &s0_, NULL);\\\n"
          "    clGetEventProfilingInfo(EV, CL_PROFILING_COMMAND_END, sizeof s1_, &s1_, NULL);\\\n"
          "    gpu_ns += s1_ - s0_; done += (NN);\\\n"
          "    double now_ = rt_now();\\\n"
          "    if (now_ - tlast >= PSEC) { double el_ = now_ - t0, rate_ = el_ > 0 ? done / el_ : 0;\\\n"
          "        double busy_ = el_ > 0 ? (gpu_ns / 1e9) / el_ * 100 : 0;\\\n"
          "        if (NALL) { double fr_ = (double)done / NALL;\\\n"
          "            fprintf(stderr, \"gpu: %5.1f%%  %llu/%llu  %.3g/s  eta %.0fs  busy %.0f%%\\n\",\\\n"
          "                    fr_ * 100, done, (unsigned long long)NALL, rate_, fr_ > 0 ? el_ * (1 - fr_) / fr_ : 0, busy_);\\\n"
          "        } else fprintf(stderr, \"gpu: %llu done  %.3g/s  busy %.0f%%\\n\", done, rate_, busy_);\\\n"
          "        tlast = now_; }\\\n"
          "} while (0)\n"
          "#else\n"
          "#define DRAIN(EV, NN) ((void)(EV), (void)(NN))\n"
          "#endif\n\n", o);

    // A kernel per key, built on demand. When the low block is fixed the key is
    // the total member length T (its width and MD5 length baked); when it is
    // variable the length is per-lane, so the key is just the prefix length.
    fprintf(o, "static cl_context ctx; static cl_device_id dev;\n"
               "static cl_kernel kern[MAXW + 1];\n"
               "static cl_kernel kernel_for(int key) {\n"
               "    if (kern[key]) return kern[key];\n"
               "    const char *uo = getenv(\"RXEJIT_NO_UNROLL\") ? \" -D RXEJIT_UNROLL=0\" : \"\";\n"
               "    cl_int e; char opts[128]; snprintf(opts, sizeof opts, %s);\n",
            lowvar ? "\"-D PLEN=%d -D DGLEN=%d%s\", key, DG, uo"
                   : "\"-D T=%d -D PLEN=%d -D DGLEN=%d%s\", key, key - LOWWIDTH, DG, uo");
    fputs("    cl_program pr = clCreateProgramWithSource(ctx, 1, &KSRC, NULL, &e);\n"
          "    if (clBuildProgram(pr, 1, &dev, opts, NULL, NULL) != CL_SUCCESS) {\n"
          "        size_t ls = 0; clGetProgramBuildInfo(pr, dev, CL_PROGRAM_BUILD_LOG, 0, NULL, &ls);\n"
          "        char *log = malloc(ls + 1); clGetProgramBuildInfo(pr, dev, CL_PROGRAM_BUILD_LOG, ls, log, NULL); log[ls] = 0;\n"
          "        fprintf(stderr, \"rxejit -G: build failed:\\n%s\\n\", log); exit(2); }\n"
          "    kern[key] = clCreateKernel(pr, \"crackG\", &e);\n    return kern[key];\n}\n\n", o);

    fputs("int main(int argc, char **argv)\n{\n"
          "    if (argc < 3) { fprintf(stderr, \"usage: %s TARGETFILE PREFIXFILE\\n\", argv[0]); return 2; }\n"
          "    unsigned ntgt = 0;\n    unsigned char *tgt = load_targets(argv[1], &ntgt);\n"
          "    if (!tgt) { fprintf(stderr, \"rxejit -G: cannot read %s\\n\", argv[1]); return 2; }\n"
          "    FILE *pf = fopen(argv[2], \"rb\");\n"
          "    if (!pf) { fprintf(stderr, \"rxejit -G: cannot read %s\\n\", argv[2]); return 2; }\n"
          "    if (ntgt == 0) { fprintf(stderr, \"0 matches\\n\"); return 0; }\n\n"
          "    cl_platform_id plat; cl_int e;\n"
          "    if (clGetPlatformIDs(1, &plat, NULL) != CL_SUCCESS) { fprintf(stderr, \"rxejit -G: no OpenCL platform\\n\"); return 2; }\n"
          "    if (clGetDeviceIDs(plat, CL_DEVICE_TYPE_GPU, 1, &dev, NULL) != CL_SUCCESS) { fprintf(stderr, \"rxejit -G: no OpenCL GPU\\n\"); return 2; }\n"
          "    ctx = clCreateContext(NULL, 1, &dev, NULL, NULL, &e); CK(e);\n"
          "#if PSEC\n"
          "    cl_queue_properties qp[] = { CL_QUEUE_PROPERTIES, CL_QUEUE_PROFILING_ENABLE, 0 };\n"
          "    cl_command_queue q = clCreateCommandQueueWithProperties(ctx, dev, qp, &e); CK(e);\n"
          "#else\n"
          "    cl_command_queue q = clCreateCommandQueueWithProperties(ctx, dev, NULL, &e); CK(e);\n"
          "#endif\n\n"
          "    cl_mem mt = clCreateBuffer(ctx, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, (size_t)ntgt * DG, tgt, &e); CK(e);\n"
          "    cl_uint *hlen = calloc(MAXHITS, sizeof *hlen); unsigned char *hbuf = calloc((size_t)MAXHITS, MAXW);\n"
          "    cl_uint nhits = 0;\n"
          "    cl_mem mhl = clCreateBuffer(ctx, CL_MEM_WRITE_ONLY, (size_t)MAXHITS * sizeof(cl_uint), NULL, &e); CK(e);\n"
          "    cl_mem mhb = clCreateBuffer(ctx, CL_MEM_WRITE_ONLY, (size_t)MAXHITS * MAXW, NULL, &e); CK(e);\n"
          "    cl_mem mn = clCreateBuffer(ctx, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, sizeof nhits, &nhits, &e); CK(e);\n"
          "    cl_mem mpfx = clCreateBuffer(ctx, CL_MEM_READ_ONLY, MAXW, NULL, &e); CK(e);\n\n"
          "    cl_ulong TILE = 1ULL << 24, loN = LON;\n"
          "#if PSEC\n    double t0 = rt_now(), tlast = t0; unsigned long long gpu_ns = 0, done = 0;\n#endif\n"
          "    unsigned char rec[MAXW + 1]; int plen;\n"
          "    while (fread(rec, 1, 1, pf) == 1 && (plen = rec[0]) >= 0) {\n"
          "        if (plen > MAXW) { fprintf(stderr, \"rxejit -G: bad prefix\\n\"); return 2; }\n"
          "        if (plen && fread(rec, 1, plen, pf) != (size_t)plen) break;\n"
          "        cl_kernel k = kernel_for(KEY);\n"
          "        if (plen) CK(clEnqueueWriteBuffer(q, mpfx, CL_TRUE, 0, plen, rec, 0, NULL, NULL));\n"
          "        CK(clSetKernelArg(k, 1, sizeof loN, &loN));\n"
          "        CK(clSetKernelArg(k, 2, sizeof mpfx, &mpfx));\n"
          "        CK(clSetKernelArg(k, 3, sizeof mt, &mt));\n"
          "        CK(clSetKernelArg(k, 4, sizeof ntgt, &ntgt));\n"
          "        CK(clSetKernelArg(k, 5, sizeof mhl, &mhl));\n"
          "        CK(clSetKernelArg(k, 6, sizeof mhb, &mhb));\n"
          "        CK(clSetKernelArg(k, 7, sizeof mn, &mn));\n"
          "        /* Double-buffered: enqueue the next tile before waiting on the\n"
          "           current, so the GPU never idles on the host between launches.\n"
          "           At most two tiles in flight; drained before the next prefix\n"
          "           overwrites the shared pfx buffer. */\n"
          "        cl_event prev = NULL; cl_ulong prev_n = 0;\n"
          "        for (cl_ulong base = 0; base < loN; base += TILE) {\n"
          "            cl_ulong n = (loN - base < TILE) ? (loN - base) : TILE;\n"
          "            size_t global = (size_t)((n + 255) / 256) * 256;\n"
          "            CK(clSetKernelArg(k, 0, sizeof base, &base));\n"
          "            cl_event ev;\n"
          "            CK(clEnqueueNDRangeKernel(q, k, 1, NULL, &global, NULL, 0, NULL, &ev));\n"
          "            if (prev) { CK(clWaitForEvents(1, &prev)); DRAIN(prev, prev_n); clReleaseEvent(prev); }\n"
          "            prev = ev; prev_n = n;\n"
          "        }\n"
          "        if (prev) { CK(clWaitForEvents(1, &prev)); DRAIN(prev, prev_n); clReleaseEvent(prev); }\n"
          "    }\n"
          "    fclose(pf);\n"
          "    CK(clEnqueueReadBuffer(q, mn, CL_TRUE, 0, sizeof nhits, &nhits, 0, NULL, NULL));\n"
          "    unsigned got = nhits < MAXHITS ? nhits : MAXHITS;\n"
          "    CK(clEnqueueReadBuffer(q, mhl, CL_TRUE, 0, (size_t)got * sizeof(cl_uint), hlen, 0, NULL, NULL));\n"
          "    CK(clEnqueueReadBuffer(q, mhb, CL_TRUE, 0, (size_t)got * MAXW, hbuf, 0, NULL, NULL));\n"
          "    for (unsigned i = 0; i < got; i++) {\n"
          "        unsigned char *p = hbuf + (size_t)i * MAXW, dg[DG];\n"
          "        HASHFN(p, hlen[i], dg);\n"
          "        for (int h = 0; h < DG; h++) printf(\"%02x\", dg[h]);\n"
          "        putchar(':'); fwrite(p, 1, hlen[i], stdout); putchar('\\n');\n"
          "    }\n"
          "    if (nhits > MAXHITS) fprintf(stderr, \"rxejit -G: %u hits, only %u recorded\\n\", nhits, MAXHITS);\n"
          "    fprintf(stderr, \"%u matches\\n\", nhits);\n"
          "    free(tgt); free(hlen); free(hbuf);\n    return 0;\n}\n", o);
}

// Run argv to completion, its stdout inherited so a generated enumerator's
// output flows straight through. Returns the exit status, or -1 if it could
// not be run at all.
static int spawn(char *const argv[])
{
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) { execvp(argv[0], argv); _exit(127); }
    int st;
    if (waitpid(pid, &st, 0) < 0) return -1;
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

// Emit the C to a temp file, compile it with $CC (or cc) at -O2, run it. The
// members -- or the count -- come out on our stdout. Returns a process exit
// code.
static int compile_and_run(const char *pattern, const struct build *B,
                           int sink, const char *nmemb, const char *jobs,
                           const char *matchfile, int verbose, int hash, int psec,
                           int gpu)
{
    char dir[] = "/tmp/rxejit.XXXXXX";
    if (!mkdtemp(dir)) { perror("rxejit: mkdtemp"); return 2; }

    char src[64], exe[64];
    snprintf(src, sizeof src, "%s/m.c", dir);
    snprintf(exe, sizeof exe, "%s/m", dir);

    int ret = 0;
    FILE *f = fopen(src, "w");
    if (!f) { perror("rxejit: fopen"); ret = 2; goto done; }
    if (gpu == 4)   emit_gpu_perm(f, pattern, B, nmemb, psec);  // a permutation
    else if (gpu)   emit_gpu_hybrid(f, pattern, B, psec);       // gpu == 2, loop repeat
    else            emit(f, pattern, B, sink, nmemb, verbose, hash, psec);
    fclose(f);

    const char *cc = getenv("CC");
    if (!cc || !*cc) cc = "cc";
    char *cargv_cpu[] = { (char *)cc, "-O2", "-pthread", src, "-o", exe, NULL };
    char *cargv_gpu[] = { (char *)cc, "-O2", src, "-o", exe, "-lOpenCL", NULL };
    int rc = spawn(gpu ? cargv_gpu : cargv_cpu);
    if (rc != 0) {
        fprintf(stderr, "rxejit: the C compiler (%s) failed\n", cc);
        ret = 2; goto done;
    }
    // Argument order the generated program expects: the match file first (if
    // any), then the thread count (if any). So write gets none, count gets
    // jobs, match gets the file, threaded match gets the file then jobs.
    char *rargv[4];
    int k = 0;
    rargv[k++] = exe;
    if (matchfile) rargv[k++] = (char *)matchfile;
    if (jobs)      rargv[k++] = (char *)jobs;
    rargv[k] = NULL;
    // Pass the enumerator's own exit status back up -- the dup sink reports its
    // verdict there (0 distinct, 1 a duplicate, 2 inconclusive).
    int r = spawn(rargv);
    if (r < 0) { fprintf(stderr, "rxejit: could not run the enumerator\n"); ret = 2; }
    else       ret = r;

done:
    unlink(src);
    unlink(exe);
    rmdir(dir);
    return ret;
}

// The generic -G producer: rxejit itself. The low block is the last G wheels;
// members group into runs of P_low that share a prefix (the low wheels are the
// least significant, independent factor), so seeking to every P_low-th member
// and stripping the low bytes yields each distinct prefix. Written to a file the
// GPU consumer reads: one record of a length byte then that many prefix bytes.
static int write_prefix_file(struct rxe *rxe, const struct build *B, int G, int lowvar, const char *path)
{
    FILE *fp;
    if (lowvar) {                                 // the whole pattern is the block:
        if (!(fp = fopen(path, "wb"))) return -1;  // one empty prefix, GPU does it all
        unsigned char z = 0; int ok = fwrite(&z, 1, 1, fp) == 1;
        fclose(fp);
        return ok ? 0 : -1;
    }
    int nw = B->nw, lowwidth = 0;
    mpz_t Pl; mpz_init_set_ui(Pl, 1);
    for (int g = nw - G; g < nw; g++) { mpz_mul_ui(Pl, Pl, (unsigned long)B->w[g].n); lowwidth += B->w[g].L; }

    FILE *f = fopen(path, "wb");
    if (!f) { mpz_clear(Pl); return -1; }
    mpz_t np, idx, i;
    mpz_init(np); mpz_init(idx); mpz_init_set_ui(i, 0);
    mpz_tdiv_q(np, rxe->nitems, Pl);          // number of prefixes = N / P_low
    char buf[4096];
    int rc = 0;
    for (; mpz_cmp(i, np) < 0; mpz_add_ui(i, i, 1)) {
        mpz_mul(idx, i, Pl);
        if (rxe_seek(rxe, idx)) { rc = -1; break; }
        char *end = rxe_current(buf, (int)sizeof buf - 1, rxe);
        int mlen = (int)(end - buf), plen = mlen - lowwidth;
        if (plen < 0 || plen > 255) { rc = -1; break; }
        unsigned char lb = (unsigned char)plen;
        if (fwrite(&lb, 1, 1, f) != 1 || (plen && fwrite(buf, 1, (size_t)plen, f) != (size_t)plen)) { rc = -1; break; }
    }
    mpz_clear(Pl); mpz_clear(np); mpz_clear(idx); mpz_clear(i);
    fclose(f);
    return rc;
}

// Generate the generic consumer, compile it (-lOpenCL), have rxejit write the
// prefix file, then run the consumer over (targets, prefixes).
static int compile_and_run_generic(const char *pattern, const struct build *B,
                                   struct rxe *rxe, int G, int lowvar, const char *nmemb, const char *matchfile, int psec)
{
    char dir[] = "/tmp/rxejit.XXXXXX";
    if (!mkdtemp(dir)) { perror("rxejit: mkdtemp"); return 2; }
    char src[64], exe[64], pfx[64];
    snprintf(src, sizeof src, "%s/m.c", dir);
    snprintf(exe, sizeof exe, "%s/m", dir);
    snprintf(pfx, sizeof pfx, "%s/p.bin", dir);

    int ret = 0;
    FILE *f = fopen(src, "w");
    if (!f) { perror("rxejit: fopen"); ret = 2; goto done; }
    emit_gpu_generic(f, pattern, B, G, lowvar, nmemb, psec);
    fclose(f);

    const char *cc = getenv("CC");
    if (!cc || !*cc) cc = "cc";
    char *cargv[] = { (char *)cc, "-O2", src, "-o", exe, "-lOpenCL", NULL };
    if (spawn(cargv) != 0) { fprintf(stderr, "rxejit: the C compiler (%s) failed\n", cc); ret = 2; goto done; }

    if (write_prefix_file(rxe, B, G, lowvar, pfx)) { fprintf(stderr, "rxejit: could not enumerate the prefixes\n"); ret = 2; goto done; }

    char *rargv[] = { exe, (char *)matchfile, pfx, NULL };
    int r = spawn(rargv);
    if (r < 0) { fprintf(stderr, "rxejit: could not run the enumerator\n"); ret = 2; }
    else       ret = r;

done:
    unlink(src); unlink(exe); unlink(pfx); rmdir(dir);
    return ret;
}

/* The same [:name:] word lists rxenum reads: a name.dict file, one word per
 * line, looked up in the -D directories then the current one. Resolution runs
 * at parse time; bake_dict then copies the words it needs. Lifted from rxedup. */

#define MAX_DICT_DIRS 16
static const char *dict_dirs[MAX_DICT_DIRS];
static int         ndict_dirs;

static char **load_dict_file(const char *path, int *nwords)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) return NULL;
    int cap = 64, n = 0;
    char **words = malloc(cap * sizeof *words);
    char line[1024];
    while (fgets(line, sizeof line, fp)) {
        int len = strlen(line);
        while (len && (line[len-1] == '\n' || line[len-1] == '\r')) line[--len] = 0;
        if (n == cap) { cap *= 2; words = realloc(words, cap * sizeof *words); }
        words[n] = malloc(len + 1);
        memcpy(words[n], line, len + 1);
        n++;
    }
    fclose(fp);
    *nwords = n;
    return words;
}

static int dict_resolver(const char *name)
{
    for (int d = -1; d < ndict_dirs; d++) {
        char path[1024];
        const char *dir = d < 0 ? "." : dict_dirs[d];
        snprintf(path, sizeof path, "%s/%s.dict", dir, name);
        int nwords;
        char **words = load_dict_file(path, &nwords);
        if (!words) continue;
        rxe_register_dict(name, (const char **)words, nwords);
        for (int i = 0; i < nwords; i++) free(words[i]);
        free(words);
        return 1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    const char *prog = argc > 0 ? argv[0] : "rxejit";
    int emit_only = 0, sink = SINK_WRITE, verbose = 0, hash = 0, psec = 0, gpu = 0, opt;
    const char *jobs = NULL;              // thread count, forwarded to the exe
    const char *matchfile = NULL;         // target file for -m

    while ((opt = getopt(argc, argv, "SGndvj:m:H:D:p:h")) != -1) {
        switch (opt) {
            case 'S': emit_only = 1; break;
            case 'G': gpu = 1; break;
            case 'p': psec = atoi(optarg);
                      if (psec < 1) { fprintf(stderr, "%s: -p needs seconds >= 1\n", prog); return 2; }
                      break;
            case 'n': sink = SINK_COUNT; break;
            case 'd': sink = SINK_DUP; break;
            case 'v': verbose = 1; break;
            case 'j': jobs = optarg; break;
            case 'm': sink = SINK_MATCH; matchfile = optarg; break;
            case 'D': if (ndict_dirs < MAX_DICT_DIRS) dict_dirs[ndict_dirs++] = optarg; break;
            case 'H': sink = SINK_MATCH; hash = 1; {
                      int ok = 0;
                      for (size_t i = 0; i < sizeof HASHES / sizeof *HASHES; i++)
                          if (strcmp(optarg, HASHES[i].name) == 0) { HA = &HASHES[i]; ok = 1; break; }
                      if (!ok) {
                          fprintf(stderr, "%s: -H: unknown hash '%s' (md5, ntlm, sha1, sha256)\n", prog, optarg);
                          return 2;
                      }
                      break; }
            case 'h':
            default:
                fprintf(stderr,
"usage: %s [-S] [-n | -m file [-H md5|ntlm|sha1|sha256] | -d [-v]] [-j jobs] REGEX\n"
"  Compile the set REGEX describes into C and run it, enumerating the members.\n"
"  Handles any finite pattern -- masks, alternations, bounded repeats,\n"
"  dictionaries, backreferences, combinations and permutations (re){{...}}.\n"
"  Only an unbounded (infinite) repeat, or a set too large to unroll, is\n"
"  declined, with a reason.\n"
"    -S       print the generated C to stdout instead of compiling and running it.\n"
"    -n       count the members rather than print them (times the walk, no I/O).\n"
"    -m file  print only the members present in 'file' (one target per line):\n"
"             the mask is a keyspace, 'file' the set to sift it against.\n"
"    -H alg   with -m, 'file' holds hex digests of one hash (md5, ntlm, sha1,\n"
"             or sha256): hash each candidate and print <digest>:<plaintext>\n"
"             for a hit -- keycracking. ntlm is MD4(UTF-16LE), the Windows hash.\n"
"    -d       report duplicate members: hash each into a per-thread set and\n"
"             merge at the join. Exit 0 if all distinct, 1 if a duplicate.\n"
"    -v       with -d, list the repeated members and their counts.\n"
"    -j jobs  threads for -n, -m and -d (default: one per CPU). Printing stays\n"
"             single-threaded and ordered.\n"
"    -p sec   every 'sec' seconds print progress to stderr -- percent done,\n"
"             rate, elapsed and ETA (the threaded -n and -m runs, and -G, which\n"
"             also reports GPU occupancy: the fraction of time the device is busy).\n"
"    -G       run on the GPU via OpenCL: one lane per candidate. Masks, uneven\n"
"             alternations, dictionaries, head-side backrefs, and combinations\n"
"             / permutations, with -m file -H md5|ntlm|sha1|sha256 (keycracking).\n"
"    -D dir   also look in 'dir' for a [:name:] dictionary's name.dict file.\n",
                    prog);
                return opt == 'h' ? 0 : 2;
        }
    }
    if (hash && !matchfile) {
        fprintf(stderr, "%s: -H needs -m with a file of digests\n", prog);
        return 2;
    }
    if (gpu && !(hash && matchfile)) {
        fprintf(stderr, "%s: -G is keycracking -- it needs -m file -H md5|ntlm|sha1|sha256\n", prog);
        return 2;
    }
    if (optind != argc - 1) {
        fprintf(stderr, "usage: %s [-S] [-n | -m file [-H md5|ntlm|sha1|sha256] | -d [-v]] [-j jobs] REGEX\n", prog);
        return 2;
    }
    const char *pattern = argv[optind];

    rxe_init();
    rxe_set_dict_resolver(dict_resolver);
    atexit(rxe_free_dicts);
    struct rxe *rxe = rxe_parse(pattern, 0);
    if (rxe_error(rxe) != RXE_OK) {
        fprintf(stderr, "%s: %s\n", prog, rxe_error_message(rxe));
        rxe_free(rxe);
        return 2;
    }

    struct build b;
    int nw = rxe_lay_build(&b, rxe);
    int ret;
    if (nw < 0) {
        fprintf(stderr, "%s: cannot compile this pattern yet -- it has %s.\n",
                prog, rxe_lay_reason());
        ret = 1;
    } else if (b.lr_active && sink == SINK_DUP) {
        fprintf(stderr, "%s: cannot compile this pattern yet -- it has "
                "a large variable-count repeat with the dedup sink.\n", prog);
        ret = 1;
    } else if (b.perm_active && sink == SINK_DUP) {
        fprintf(stderr, "%s: cannot compile this pattern yet -- it has "
                "a permutation with the dedup sink.\n", prog);
        ret = 1;
    } else {
        // The member total, baked in so the threaded count can split [0, N).
        // Left NULL when it overflows 64 bits, which keeps that count on one
        // thread -- a set that large is past enumerating whole regardless.
        mpz_t N;
        mpz_init_set_ui(N, 1);
        for (int i = 0; i < nw; i++) mpz_mul_ui(N, N, (unsigned long)b.w[i].n);
        if (b.lr_active) {
            // Fold in the repeat super-wheel's radix M = sum_{k=a}^{b} C^k, where
            // C is the members of one body copy. (b.w is only the pre/post
            // wheels; the body was lifted into lr_sw.)
            mpz_t Cz, term, M;
            mpz_init_set_ui(Cz, 1);
            for (int j = 0; j < b.lr_nsw; j++) mpz_mul_ui(Cz, Cz, (unsigned long)b.lr_sw[j].n);
            mpz_init(term); mpz_init_set_ui(M, 0);
            for (int k = b.lr_a; k <= b.lr_b; k++) {
                mpz_pow_ui(term, Cz, (unsigned long)k);
                mpz_add(M, M, term);
            }
            mpz_mul(N, N, M);
            mpz_clear(Cz); mpz_clear(term); mpz_clear(M);
        }
        if (b.perm_active) {
            // Fold in the choice super-wheel's radix sum_{s=lo}^{hi} of the block
            // -- P(n,s) ordered, C(n,s) unordered.
            mpz_t blk, sum;
            mpz_init(blk);
            mpz_init_set_ui(sum, 0);
            for (int s = b.perm_lo; s <= b.perm_hi; s++) {
                if (b.perm_ordered) {
                    mpz_set_ui(blk, 1);
                    for (int t = 0; t < s; t++) mpz_mul_ui(blk, blk, (unsigned long)(b.perm_pool.n - t));
                } else {
                    mpz_bin_uiui(blk, (unsigned long)b.perm_pool.n, (unsigned long)s);
                }
                mpz_add(sum, sum, blk);
            }
            mpz_mul(N, N, sum);
            mpz_clear(blk); mpz_clear(sum);
        }
        char nbuf[32];
        const char *nmemb = NULL;
        if (mpz_fits_ulong_p(N)) { gmp_snprintf(nbuf, sizeof nbuf, "%Zu", N); nmemb = nbuf; }

        // The GPU path is a fixed-width mask only: a lane rebuilds its candidate
        // from its index at a constant width, no per-lane length divergence, and
        // the candidate must fit one MD5 block (< 56 bytes). Everything a
        // variable render needs -- a variable wheel, a backref, a loop repeat --
        // is declined here, so the CPU stays the answer for those.
        const char *gpu_no = NULL;
        int gpu_kind = 0;                       // 1 fixed mask, 2 loop repeat, 3 generic
        int gpu_G = 0, gpu_lowvar = 0;
        if (gpu && b.perm_active) {
            // A choice runs whole on the GPU: each lane unranks its index. The
            // widest candidate must fit one hash block. The pool itself is a
            // __global buffer, so a big dictionary is fine; only an unordered
            // choice's Pascal table (baked into the program source) is capped.
            // The unrank is O(k), so nothing pool-wide sits in private memory.
            int poolmax = b.perm_pool.L;
            if (!b.perm_pool.L)
                for (int j = 0; j < b.perm_pool.n; j++)
                    if (b.perm_pool.alen[j] > poolmax) poolmax = b.perm_pool.alen[j];
            int maxw = b.perm_hi * poolmax;
            for (int i = 0; i < nw; i++) {
                int wm = b.w[i].L;
                if (wm == 0) for (int j = 0; j < b.w[i].n; j++) if (b.w[i].alen[j] > wm) wm = b.w[i].alen[j];
                maxw += wm;
            }
            if (maxw * HA->mfac >= 56) gpu_no = "a candidate too wide for one hash block";
            else if (!b.perm_ordered && (b.perm_pool.n + 1) * (b.perm_hi + 1) > (1 << 20))
                gpu_no = "an unordered choice whose binomial table is too large for the GPU";
            else if (!nmemb) gpu_no = "more members than fit 64 bits";
            else gpu_kind = 4;
        } else if (gpu && b.lr_active) {
            // A loop repeat runs on the GPU split by length -- but only a bare,
            // single-wheel body for now ([a-z]{1,8}); surrounding or multi-wheel
            // structure is not yet handled and stays on the CPU.
            if (b.nw != 0 || b.lr_nsw != 1 || b.has_backref)
                gpu_no = "a loop repeat with surrounding or multi-wheel structure";
            else if (b.lr_b * b.lr_sw[0].L * HA->mfac >= 56) gpu_no = "a candidate too wide for one hash block";
            else if (!nmemb) gpu_no = "more members than fit 64 bits";
            else gpu_kind = 2;
        } else if (gpu) {
            // A fixed mask is one grid; a pattern with structure but a fixed-class
            // tail is the generic split -- rxejit enumerates the head (backrefs
            // and all), the GPU sweeps the tail. The candidate must fit one MD5
            // block, backref copies counted.
            int anyvar = b.has_backref;             // a backref makes the render variable
            for (int i = 0; i < nw; i++) if (b.w[i].L == 0) anyvar = 1;
            int totw = gpu_maxwidth(&b);
            if (totw * HA->mfac >= 56) gpu_no = "a candidate too wide for one hash block";
            else if (!anyvar) {                     // a pure fixed mask: the whole
                if (!nmemb) gpu_no = "more members than fit 64 bits";   // thing is
                else { gpu_kind = 3; gpu_G = nw; }  // the low block, one empty prefix
            } else {
                // The low block: the largest fixed-class tail whose sweep is a fat
                // batch (>= ~1M) and stays a sane width, leaving a non-empty head.
                // Walked over the ops from the end, so a backref copy (OP_COPY) or
                // a group boundary ends it -- a backref that straddles into the
                // tail declines, only a head-side one is taken.
                int lowwidth = 0, expect = nw - 1; unsigned long long Plow = 1;
                for (int k = b.nops - 1; k >= 0; k--) {
                    struct op op = b.ops[k];
                    if (op.kind != OP_LAY || op.arg != expect) break;
                    struct wheel *lwh = &b.w[op.arg];
                    if (lwh->L == 0 || lowwidth + lwh->L > 40 || Plow >= (1ULL << 32)) break;
                    lowwidth += lwh->L; Plow *= (unsigned long long)lwh->n; gpu_G++; expect--;
                }
                if (gpu_G >= 1 && gpu_G < nw && Plow >= (1u << 20)) gpu_kind = 3;
                else if (!b.has_backref && nmemb && mpz_cmp_ui(N, 1u << 20) >= 0) {
                    // No fixed tail worth splitting -- a variable dictionary or
                    // uneven alternation. Lay the whole pattern compactly on the
                    // GPU instead (each alternative's real bytes, running length).
                    gpu_G = nw; gpu_lowvar = 1; gpu_kind = 3;
                } else gpu_no = "no fixed-class tail or dictionary large enough for the GPU";
            }
        }

        if (gpu && gpu_no) {
            fprintf(stderr, "%s: the GPU path needs a fixed mask, a bare X{a,b}, or a "
                    "fixed-class tail -- this has %s.\n", prog, gpu_no);
            ret = 1;
        } else if (emit_only && gpu_kind == 4) { emit_gpu_perm(stdout, pattern, &b, nmemb, psec); ret = 0; }
        else if (emit_only && gpu_kind == 3) { emit_gpu_generic(stdout, pattern, &b, gpu_G, gpu_lowvar, nmemb, psec); ret = 0; }
        else if (emit_only && gpu_kind == 2) { emit_gpu_hybrid(stdout, pattern, &b, psec); ret = 0; }
        else if (emit_only) { emit(stdout, pattern, &b, sink, nmemb, verbose, hash, psec); ret = 0; }
        else if (gpu_kind == 3) ret = compile_and_run_generic(pattern, &b, rxe, gpu_G, gpu_lowvar, nmemb, matchfile, psec);
        else if (gpu)       ret = compile_and_run(pattern, &b, sink, nmemb, NULL, matchfile, verbose, hash, psec, gpu_kind);
        else                ret = compile_and_run(pattern, &b, sink, nmemb, jobs, matchfile, verbose, hash, psec, 0);
        mpz_clear(N);
    }

    rxe_lay_free(&b);
    rxe_free(rxe);
    return ret;
}
