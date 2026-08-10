/*
 * rxerank - the inverse of rxenum. Given a regex and one or more strings, print
 *           the index each string sits at in the set the regex describes. Where
 *           rxenum turns an index into a member, rxerank turns a member back
 *           into its index -- rank, the inverse of seek.
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
#include <getopt.h>
#include "rxe.h"

// rxenum numbers its members from one by default and from zero under -z; rxerank
// follows, so the index it prints is the one 'rxenum -f' takes. The library
// itself is zero-based, so the offset is added to what rank returns.
static long g_offset = 1;
static int  g_prefix = 0;         // print "string<TAB>" before each index
static const char *g_cur;         // the string being ranked, for the prefix

enum { MODE_FIRST, MODE_ALL, MODE_COUNT, MODE_QUIET };

static void die(const char *fmt, ...);

static void put_prefix(void)
{
    if (g_prefix) printf("%s\t", g_cur);
}

struct all_state { int any; };
static int print_index(const mpz_t idx, void *v)
{
    struct all_state *a = v;
    a->any = 1;
    mpz_t t;
    mpz_init(t);
    mpz_add_ui(t, idx, g_offset);
    put_prefix();
    gmp_printf("%Zd\n", t);
    mpz_clear(t);
    return 0;                     // never stop: a listing wants them all
}

// Rank one string. Returns 0 if it is a member, 1 if not, -1 if the set is one
// rank cannot handle (the reason is the same for every string, so the caller
// stops at the first such).
static int rank_one(struct rxe *rxe, const char *s, int mode)
{
    g_cur = s;
    if (mode == MODE_COUNT) {
        mpz_t c;
        mpz_init(c);
        if (rxe_rank_count(rxe, s, c) < 0) { mpz_clear(c); return -1; }
        put_prefix();
        gmp_printf("%Zd\n", c);
        int member = mpz_sgn(c) > 0;
        mpz_clear(c);
        return member ? 0 : 1;
    }
    if (mode == MODE_ALL) {
        struct all_state a = { 0 };
        if (rxe_rank_all(rxe, s, print_index, &a) < 0) return -1;
        return a.any ? 0 : 1;
    }
    mpz_t idx;
    mpz_init(idx);
    int rc = rxe_rank(rxe, s, idx);
    if (rc == 0 && mode == MODE_FIRST) {
        mpz_add_ui(idx, idx, g_offset);
        put_prefix();
        gmp_printf("%Zd\n", idx);
    }
    mpz_clear(idx);
    return rc;                    // 0 member, 1 not, -1 refused
}

int main(int argc, char **argv)
{
    if (argc < 2)
        die("Usage: rxerank [-is] [-z] [-a|-c|-q] <regex> [string ...]\n"
            "  -a  list every index the string reaches (duplicates included)\n"
            "  -c  print how many indices it reaches (>1 means a duplicate)\n"
            "  -q  quiet: no output, exit status is membership\n"
            "  -z  number from zero, as rxenum -z (default is from one)\n"
            "With no strings, they are read from standard input, one per line.\n");

    int flags = 0, mode = MODE_FIRST, nmode = 0;
    for (;;) {
        int o = getopt(argc, argv, "iszacq");
        if (o < 0) break;
        switch (o) {
            case 'i': flags |= RXE_CASELESS; break;
            case 's': flags |= RXE_DOTALL;   break;
            case 'z': g_offset = 0;          break;
            case 'a': mode = MODE_ALL;   nmode++; break;
            case 'c': mode = MODE_COUNT; nmode++; break;
            case 'q': mode = MODE_QUIET; nmode++; break;
            default:  die("Unknown option\n");
        }
    }
    if (nmode > 1) die("-a, -c and -q are mutually exclusive\n");
    if (!argv[optind]) die("missing regex\n");

    const char *pat = argv[optind];
    char **strv = &argv[optind + 1];
    int nstr = argc - (optind + 1);
    int from_stdin = (nstr == 0);
    // In listing mode one string yields many lines, so tag each with its
    // string when there is more than one to keep them apart. The other modes
    // print one line per string and stay a clean filter.
    g_prefix = (mode == MODE_ALL) && (from_stdin || nstr > 1);

    struct rxe *rxe = rxe_parse(pat, flags);
    if (rxe_error(rxe)) {
        int pos = rxe_error_pos(rxe), len = (int)strlen(pat);
        if (pos < 0) pos = 0;
        if (pos > len) pos = len;
        fprintf(stderr, "%s\n", rxe_error_message(rxe));
        fprintf(stderr, "    %s\n", pat);
        fprintf(stderr, "    %*s^\n", pos, "");
        return 1;
    }

    int status = 0;               // 1 if any string was not a member
    if (from_stdin) {
        char *line = NULL;
        size_t cap = 0;
        ssize_t n;
        while ((n = getline(&line, &cap, stdin)) >= 0) {
            if (n && line[n - 1] == '\n') line[--n] = 0;   // strip newline
            int rc = rank_one(rxe, line, mode);
            if (rc < 0) { fprintf(stderr, "rxerank: cannot rank this set: %s\n",
                                  rxe_rank_reason()); free(line); rxe_free(rxe);
                          return 2; }
            if (rc > 0) status = 1;
        }
        free(line);
    } else {
        for (int i = 0; i < nstr; i++) {
            int rc = rank_one(rxe, strv[i], mode);
            if (rc < 0) { fprintf(stderr, "rxerank: cannot rank this set: %s\n",
                                  rxe_rank_reason()); rxe_free(rxe); return 2; }
            if (rc > 0) status = 1;
        }
    }
    rxe_free(rxe);
    return status;
}

#include <stdarg.h>
static void die(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    exit(1);
}
