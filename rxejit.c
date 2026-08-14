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
 *          This first cut handles the fixed-width mask -- a run of single-
 *          character classes and their exact repeats, [a-z]{4}[0-9]{2} and the
 *          like, the classic shape of a mask attack. Anything else (an
 *          alternation, a dictionary, an unbounded or variable repeat, a
 *          backreference) it declines, naming what it could not take, so the
 *          interpreter path stays the answer for those. The C it prints is a
 *          standalone program that writes every member to stdout, in exactly
 *          rxenum -e's order; a later cut compiles and runs it, and swaps the
 *          write for a chosen sink.
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

#define MAXW 4096                  // most positions an unrolled mask may have

// What the generated loop does with each member. write is the default -- the
// members to stdout, as rxenum -e does; count only tallies them, which is how
// to time the enumeration itself with no I/O in the way.
enum { SINK_WRITE, SINK_COUNT };

// One odometer wheel: the ordered bytes a single position steps through, drawn
// straight from a class node's string so the order is the enumeration's.
struct wheel { const char *a; int n; };

static const char *reason;         // why a pattern was declined, for the message

// A plain single-character class -- none of the compound flags, no
// subexpression -- yields one wheel. Returns 0 and fills a/n, or -1.
static int class_of(struct rxe_node *nd, const char **a, int *n)
{
    if (nd->is_repeat || nd->is_comb || nd->is_shuffle ||
        nd->is_dict || nd->is_backref || nd->is_inf || nd->rxe)
        return -1;
    *a = nd->str;
    *n = nd->len;
    return 0;
}

// Flatten a mask into its wheels, left to right. Returns the count, or -1 with
// 'reason' set for the first thing that is not a fixed run of classes.
static int collect(struct rxe *rxe, struct wheel *w)
{
    if (rxe->flags & (RXE_FLAG_LEFT_TO_RIGHT | RXE_FLAG_SHORTLEX)) {
        reason = "a non-default enumeration order"; return -1;
    }
    if (!rxe->head || rxe->head->next) {       // more than one alternation
        reason = "a top-level alternation"; return -1;
    }
    int nw = 0;
    for (struct rxe_node *nd = rxe->head->head; nd; nd = nd->next) {
        const char *a; int n, reps = 1;
        if (class_of(nd, &a, &n) != 0) {
            // The one compound we take: an exact {k} repeat of a plain class.
            struct rxe *b = nd->rxe;
            if (nd->is_repeat && !nd->is_inf && nd->rep_max != RXE_REP_UNBOUNDED &&
                nd->rep_min == nd->rep_max &&
                b && b->head && !b->head->next && b->head->head &&
                !b->head->head->next && class_of(b->head->head, &a, &n) == 0) {
                reps = nd->rep_min;
            } else {
                reason = nd->is_inf     ? "an unbounded repeat"
                       : nd->is_dict    ? "a dictionary"
                       : nd->is_backref ? "a backreference"
                       : nd->is_comb    ? "a combination"
                       : nd->is_shuffle ? "a shuffle"
                       : nd->is_repeat  ? "a variable-count repeat"
                       : nd->rxe        ? "a group"
                       :                  "an unsupported element";
                return -1;
            }
        }
        if (n < 1) { reason = "an empty class"; return -1; }
        for (int k = 0; k < reps; k++) {
            if (nw >= MAXW) { reason = "too many positions to unroll"; return -1; }
            w[nw].a = a; w[nw].n = n; nw++;
        }
    }
    return nw;
}

// Print the pattern into a C comment, defusing any */ that would close it.
static void emit_comment(FILE *o, const char *s)
{
    for (; *s; s++) fputc((*s == '*' && s[1] == '/') ? ' ' : *s, o);
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
static void emit(FILE *o, const char *pattern, struct wheel *w, int nw,
                 int sink, const char *nmemb)
{
    int count    = sink == SINK_COUNT;
    int threaded = count && nmemb;

    fputs("/* generated by rxejit from: ", o);
    emit_comment(o, pattern);
    fputs(" */\n#include <stdio.h>\n", o);
    if (threaded) fputs("#include <stdlib.h>\n#include <pthread.h>\n#include <unistd.h>\n", o);
    fputc('\n', o);

    fputs(count
        ? "static void run(unsigned long long from, unsigned long long count, unsigned long long *acc)\n{\n"
        : "static void run(unsigned long long from, unsigned long long count)\n{\n", o);

    for (int i = 0; i < nw; i++) {
        fprintf(o, "    static const unsigned char A%d[] = {", i);
        for (int j = 0; j < w[i].n; j++)
            fprintf(o, "%s%d", j ? "," : "", (unsigned char)w[i].a[j]);
        fputs("};\n", o);
    }

    fprintf(o, "    unsigned char buf[%d];\n", nw + 1);
    fprintf(o, "    buf[%d] = '\\n';\n", nw);

    // Seed each wheel from 'from': digit = from %% radix, then from /= radix,
    // walking from the least significant wheel up, so the buffer starts on the
    // member at index 'from' rather than always at zero.
    fputs("    unsigned long long f = from;\n", o);
    for (int i = nw - 1; i >= 0; i--)
        fprintf(o, "    int i%d = f %% %d; f /= %d;\n", i, w[i].n, w[i].n);
    for (int i = 0; i < nw; i++)
        fprintf(o, "    buf[%d] = A%d[i%d];\n", i, i, i);

    if (count) fputs("    unsigned long long n = 0;\n", o);
    fputs("    unsigned long long done = 0;\n", o);
    fputs("    for (;;) {\n", o);
    if (count) fputs("        n++;\n", o);
    else       fprintf(o, "        fwrite(buf, 1, %d, stdout);\n", nw + 1);
    fputs("        if (count && ++done == count) break;\n", o);
    for (int i = nw - 1; i >= 0; i--)
        fprintf(o, "        if (++i%d < %d) { buf[%d] = A%d[i%d]; continue; }"
                   " i%d = 0; buf[%d] = A%d[0];\n",
                i, w[i].n, i, i, i, i, i, i);
    fputs("        break;\n    }\n", o);
    if (count) fputs("    *acc += n;\n", o);
    fputs("}\n\n", o);

    if (threaded) {
        fprintf(o,
"#define NMEMB %sULL\n"
"#define MAXT  256\n\n"
"struct shard { unsigned long long from, count, total; };\n\n"
"static void *worker(void *p)\n{\n"
"    struct shard *s = p;\n"
"    s->total = 0;\n"
"    run(s->from, s->count, &s->total);\n"
"    return 0;\n"
"}\n\n"
"int main(int argc, char **argv)\n{\n"
"    long np = sysconf(_SC_NPROCESSORS_ONLN);\n"
"    int T = np < 1 ? 1 : (int)np;\n"
"    if (argc > 1) { int j = atoi(argv[1]); if (j > 0) T = j; }\n"
"    if (T > MAXT) T = MAXT;\n"
"    unsigned long long N = NMEMB;\n"
"    if (N == 0) { printf(\"0\\n\"); return 0; }\n"
"    if (N < (unsigned long long)T) T = (int)N;\n"   /* only when N < MAXT, so the cast is small */
"    struct shard sh[MAXT];\n"
"    pthread_t   tid[MAXT];\n"
"    unsigned long long base = N / (unsigned long long)T,\n"
"                       rem  = N %% (unsigned long long)T, off = 0;\n"
"    for (int t = 0; t < T; t++) {\n"
"        sh[t].from = off;\n"
"        sh[t].count = base + ((unsigned long long)t < rem ? 1 : 0);\n"
"        off += sh[t].count;\n"
"    }\n"
"    for (int t = 1; t < T; t++) pthread_create(&tid[t], 0, worker, &sh[t]);\n"
"    worker(&sh[0]);\n"
"    for (int t = 1; t < T; t++) pthread_join(tid[t], 0);\n"
"    unsigned long long total = 0;\n"
"    for (int t = 0; t < T; t++) total += sh[t].total;\n"
"    printf(\"%%llu\\n\", total);\n"
"    return 0;\n"
"}\n", nmemb);
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
static int compile_and_run(const char *pattern, struct wheel *w, int nw,
                           int sink, const char *nmemb, const char *jobs)
{
    char dir[] = "/tmp/rxejit.XXXXXX";
    if (!mkdtemp(dir)) { perror("rxejit: mkdtemp"); return 2; }

    char src[64], exe[64];
    snprintf(src, sizeof src, "%s/m.c", dir);
    snprintf(exe, sizeof exe, "%s/m", dir);

    int ret = 0;
    FILE *f = fopen(src, "w");
    if (!f) { perror("rxejit: fopen"); ret = 2; goto done; }
    emit(f, pattern, w, nw, sink, nmemb);
    fclose(f);

    const char *cc = getenv("CC");
    if (!cc || !*cc) cc = "cc";
    char *cargv[] = { (char *)cc, "-O2", "-pthread", src, "-o", exe, NULL };
    int rc = spawn(cargv);
    if (rc != 0) {
        fprintf(stderr, "rxejit: the C compiler (%s) failed\n", cc);
        ret = 2; goto done;
    }
    // The generated program reads its thread count from argv[1]; forward -j.
    char *rargv[] = { exe, (char *)jobs, NULL };
    if (!jobs) rargv[1] = NULL;
    if (spawn(rargv) < 0) { fprintf(stderr, "rxejit: could not run the enumerator\n"); ret = 2; }

done:
    unlink(src);
    unlink(exe);
    rmdir(dir);
    return ret;
}

int main(int argc, char **argv)
{
    const char *prog = argc > 0 ? argv[0] : "rxejit";
    int emit_only = 0, sink = SINK_WRITE, opt;
    const char *jobs = NULL;              // thread count for -n, forwarded to the exe

    while ((opt = getopt(argc, argv, "Snj:h")) != -1) {
        switch (opt) {
            case 'S': emit_only = 1; break;
            case 'n': sink = SINK_COUNT; break;
            case 'j': jobs = optarg; break;
            case 'h':
            default:
                fprintf(stderr,
"usage: %s [-S] [-n] [-j jobs] REGEX\n"
"  Compile the set REGEX describes into C and run it, enumerating the members.\n"
"  Handles a fixed-width mask of single-character classes; other patterns are\n"
"  declined with a reason.\n"
"    -S       print the generated C to stdout instead of compiling and running it.\n"
"    -n       count the members rather than print them (times the walk, no I/O).\n"
"    -j jobs  threads for the -n count (default: one per CPU). Printing stays\n"
"             single-threaded and ordered.\n",
                    prog);
                return opt == 'h' ? 0 : 2;
        }
    }
    if (optind != argc - 1) {
        fprintf(stderr, "usage: %s [-S] [-n] [-j jobs] REGEX\n", prog);
        return 2;
    }
    const char *pattern = argv[optind];

    rxe_init();
    struct rxe *rxe = rxe_parse(pattern, 0);
    if (rxe_error(rxe) != RXE_OK) {
        fprintf(stderr, "%s: %s\n", prog, rxe_error_message(rxe));
        rxe_free(rxe);
        return 2;
    }

    struct wheel *w = malloc(MAXW * sizeof *w);
    if (!w) { fprintf(stderr, "%s: out of memory\n", prog); rxe_free(rxe); return 2; }

    int nw = collect(rxe, w);
    int ret;
    if (nw < 0) {
        fprintf(stderr, "%s: cannot compile this pattern yet -- it has %s.\n",
                prog, reason);
        ret = 1;
    } else {
        // The member total, baked in so the threaded count can split [0, N).
        // Left NULL when it overflows 64 bits, which keeps that count on one
        // thread -- a set that large is past enumerating whole regardless.
        mpz_t N;
        mpz_init_set_ui(N, 1);
        for (int i = 0; i < nw; i++) mpz_mul_ui(N, N, (unsigned long)w[i].n);
        char nbuf[32];
        const char *nmemb = NULL;
        if (mpz_fits_ulong_p(N)) { gmp_snprintf(nbuf, sizeof nbuf, "%Zu", N); nmemb = nbuf; }

        if (emit_only) { emit(stdout, pattern, w, nw, sink, nmemb); ret = 0; }
        else           ret = compile_and_run(pattern, w, nw, sink, nmemb, jobs);
        mpz_clear(N);
    }

    free(w);
    rxe_free(rxe);
    return ret;
}
