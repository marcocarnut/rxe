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
 *          It handles the fixed-width case: single-character classes, their
 *          exact repeats, and alternations whose branches are all the same
 *          length -- [a-z]{4}[0-9]{2}, (cat|dog)[0-9], the classic mask attack
 *          and a little past it. Each position is a "wheel" of L-byte
 *          alternatives (a class is L=1, an equal-length alternation L>1, baked
 *          out by the interpreter). What it cannot make fixed-width -- an
 *          alternation of uneven lengths, an unbounded or variable repeat, a
 *          dictionary, a backreference -- it declines, naming the reason, so the
 *          interpreter path stays the answer there. It runs the compiled program
 *          (or prints the C with -S) with a chosen sink: write, count, or match.
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

#define MAXW 4096                  // most positions an unrolled mask may have

// What the generated loop does with each member. write is the default -- the
// members to stdout, as rxenum -e does; count only tallies them, which times
// the enumeration with no I/O in the way; match probes each against a target
// set loaded at runtime and prints the hits (a mask being a keyspace to sift);
// dup hashes each into a per-thread set and reports the repeats, merged at the
// join -- meaningful now that alternations put duplicates in the set.
enum { SINK_WRITE, SINK_COUNT, SINK_MATCH, SINK_DUP };

#define ALT_CAP 65536              // most members a baked alternation may hold

// One odometer wheel: n alternatives, each L bytes, at 'base' laid end to end
// (alternative i is base + i*L). A character class is the L==1 case, its bytes
// the class string; an alternation of equal-length branches is L>1, its bytes
// the members baked out by the interpreter. Stepping the wheel copies L bytes.
struct wheel { const char *base; int n; int L; };

static const char *reason;         // why a pattern was declined, for the message

// The running build: the wheels gathered so far, plus the buffers baked for
// alternations (freed once the code is emitted).
struct build {
    struct wheel *w;
    int           nw;
    char        **bake;
    int           nbake, cbake;
};

static int add_wheel(struct build *b, const char *base, int n, int L)
{
    if (n < 1)         { reason = "an empty class"; return -1; }
    if (b->nw >= MAXW) { reason = "too many positions to unroll"; return -1; }
    b->w[b->nw].base = base; b->w[b->nw].n = n; b->w[b->nw].L = L;
    b->nw++;
    return 0;
}

static int add_rxe(struct build *b, struct rxe *rxe);

// An alternation becomes one wheel by baking its members: enumerate them with
// the interpreter, in seek order -- the very order the parent odometer drives
// this position through -- and store them as the wheel's alternatives. They
// must all be the same byte length (the flat buffer has no room for a position
// that changes width) and few enough to unroll. Duplicate branches like (a|a)
// bake to repeated alternatives, so the odometer visits the repeat and a dedup
// sink can see it -- which is the point of taking alternations at all.
static int bake_alt(struct build *b, struct rxe *rxe)
{
    if (rxe->ninf || !mpz_fits_ulong_p(rxe->nitems)) {
        reason = "an alternation too large to unroll"; return -1;
    }
    unsigned long n = mpz_get_ui(rxe->nitems);
    if (n < 1)       { reason = "an empty alternation"; return -1; }
    if (n > ALT_CAP) { reason = "an alternation too large to unroll"; return -1; }

    char tmp[4096];
    mpz_t idx;
    mpz_init(idx);
    int L = -1;
    char *buf = NULL;
    for (unsigned long i = 0; i < n; i++) {
        mpz_set_ui(idx, i);
        if (rxe_seek(rxe, idx)) { reason = "an alternation that would not seek"; goto fail; }
        char *end = rxe_current(tmp, (int)sizeof tmp - 1, rxe);
        int len = (int)(end - tmp);
        if (i == 0) {
            L = len;
            if (L < 1 || L >= (int)sizeof tmp - 1) { reason = "an alternation member too long"; goto fail; }
            buf = malloc((size_t)n * L);
            if (!buf) { reason = "out of memory"; goto fail; }
        } else if (len != L) {
            reason = "an alternation with uneven member lengths"; goto fail;
        }
        memcpy(buf + (size_t)i * L, tmp, L);
    }
    mpz_clear(idx);

    if (b->nbake == b->cbake) {
        int nc = b->cbake ? b->cbake * 2 : 8;
        char **nb = realloc(b->bake, (size_t)nc * sizeof *nb);
        if (!nb) { free(buf); reason = "out of memory"; return -1; }
        b->bake = nb; b->cbake = nc;
    }
    b->bake[b->nbake++] = buf;
    return add_wheel(b, buf, (int)n, L);
fail:
    free(buf);
    mpz_clear(idx);
    return -1;
}

// One node -> wheel(s): a plain class is one L==1 wheel; an exact {k} repeat is
// its body's wheels laid down k times; a group recurses into its subexpression.
static int add_node(struct build *b, struct rxe_node *nd)
{
    int plain = !nd->is_repeat && !nd->is_comb && !nd->is_shuffle &&
                !nd->is_dict && !nd->is_backref && !nd->is_inf && !nd->rxe;
    if (plain)
        return add_wheel(b, nd->str, nd->len, 1);

    if (nd->is_repeat && !nd->is_inf && nd->rep_max != RXE_REP_UNBOUNDED &&
        nd->rep_min == nd->rep_max && nd->rxe) {
        for (int k = 0; k < nd->rep_min; k++)
            if (add_rxe(b, nd->rxe)) return -1;
        return 0;
    }

    if (nd->rxe && !nd->is_repeat && !nd->is_comb && !nd->is_shuffle &&
        !nd->is_dict && !nd->is_backref && !nd->is_inf)
        return add_rxe(b, nd->rxe);

    reason = nd->is_inf     ? "an unbounded repeat"
           : nd->is_dict    ? "a dictionary"
           : nd->is_backref ? "a backreference"
           : nd->is_comb    ? "a combination"
           : nd->is_shuffle ? "a shuffle"
           : nd->is_repeat  ? "a variable-count repeat"
           :                  "an unsupported element";
    return -1;
}

// An expression -> wheels: an alternation (more than one branch) bakes to one
// wheel; a single branch is its nodes in order.
static int add_rxe(struct build *b, struct rxe *rxe)
{
    if (rxe->flags & (RXE_FLAG_LEFT_TO_RIGHT | RXE_FLAG_SHORTLEX)) {
        reason = "a non-default enumeration order"; return -1;
    }
    if (!rxe->head) { reason = "an empty expression"; return -1; }
    if (rxe->head->next)
        return bake_alt(b, rxe);
    for (struct rxe_node *nd = rxe->head->head; nd; nd = nd->next)
        if (add_node(b, nd)) return -1;
    return 0;
}

// Gather the wheels for the whole pattern. Returns the count, or -1 with
// 'reason' set. On success the caller must free the bake buffers (free_build).
static int collect(struct build *b, struct rxe *rxe)
{
    b->nw = 0; b->bake = NULL; b->nbake = 0; b->cbake = 0;
    return add_rxe(b, rxe) ? -1 : b->nw;
}

static void free_build(struct build *b)
{
    for (int i = 0; i < b->nbake; i++) free(b->bake[i]);
    free(b->bake);
}

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
                 int sink, const char *nmemb, int verbose)
{
    int count    = sink == SINK_COUNT;
    int match    = sink == SINK_MATCH;
    int dup      = sink == SINK_DUP;
    int acc      = count || match;              // sinks that tally into *acc
    int threaded = (acc || dup) && nmemb;       // split [0,N) when N fits 64 bits
    int rt       = match || dup;                // needs the embedded runtime

    // Buffer offsets: each wheel lays L bytes, so a wider one (an alternation)
    // pushes those after it along. TL is the member length; multi marks whether
    // any wheel is wider than a byte, which is when memcpy (and string.h) enter.
    int off[MAXW], TL = 0, multi = 0;
    for (int i = 0; i < nw; i++) { off[i] = TL; TL += w[i].L; if (w[i].L > 1) multi = 1; }

    fputs("/* generated by rxejit from: ", o);
    emit_comment(o, pattern);
    fputs(" */\n#include <stdio.h>\n", o);
    if (multi && !rt) fputs("#include <string.h>\n", o);      // rt sinks get it via the runtime
    // match keeps a mutex for the rare hit print even on one thread, so pthread
    // comes in for it too; count and dup need pthread only when they thread.
    if (threaded || match) fputs("#include <stdlib.h>\n#include <pthread.h>\n#include <unistd.h>\n", o);
    fputc('\n', o);

    if (rt) fputs(RXEJIT_RT, o), fputc('\n', o);
    if (match) {
        fputs("static struct rt_set TB;   /* the targets, read-only once loaded */\n", o);
        fputs("static pthread_mutex_t MX = PTHREAD_MUTEX_INITIALIZER;\n\n", o);
    }

    fputs(dup
        ? "static void run(unsigned long long from, unsigned long long count, struct rt_dup *d)\n{\n"
        : acc
        ? "static void run(unsigned long long from, unsigned long long count, unsigned long long *acc)\n{\n"
        : "static void run(unsigned long long from, unsigned long long count)\n{\n", o);

    for (int i = 0; i < nw; i++) {
        fprintf(o, "    static const unsigned char A%d[] = {", i);
        for (int j = 0; j < w[i].n * w[i].L; j++)
            fprintf(o, "%s%d", j ? "," : "", (unsigned char)w[i].base[j]);
        fputs("};\n", o);
    }

    fprintf(o, "    unsigned char buf[%d];\n", TL + 1);
    fprintf(o, "    buf[%d] = '\\n';\n", TL);

    // Seed each wheel from 'from': digit = from %% radix, then from /= radix,
    // walking from the least significant wheel up, so the buffer starts on the
    // member at index 'from' rather than always at zero.
    fputs("    unsigned long long f = from;\n", o);
    for (int i = nw - 1; i >= 0; i--)
        fprintf(o, "    int i%d = f %% %d; f /= %d;\n", i, w[i].n, w[i].n);
    for (int i = 0; i < nw; i++) {
        char e[16]; snprintf(e, sizeof e, "i%d", i);
        fputs("    ", o); emit_lay(o, i, off[i], w[i].L, e); fputc('\n', o);
    }

    if (acc) fputs("    unsigned long long n = 0;\n", o);
    fputs("    unsigned long long done = 0;\n", o);
    fputs("    for (;;) {\n", o);
    if (dup)        fprintf(o, "        rt_dup_add(d, (const char *)buf, %d);\n", TL);
    else if (match) fprintf(o, "        if (rt_set_has(&TB, (const char *)buf, %d))"
                               " { pthread_mutex_lock(&MX); fwrite(buf, 1, %d, stdout);"
                               " pthread_mutex_unlock(&MX); n++; }\n", TL, TL + 1);
    else if (count) fputs("        n++;\n", o);
    else            fprintf(o, "        fwrite(buf, 1, %d, stdout);\n", TL + 1);
    fputs("        if (count && ++done == count) break;\n", o);
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
    fputs("}\n\n", o);

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
        fprintf(o, "#define NMEMB %sULL\n#define MAXT  256\n\n", nmemb);
        fputs("struct shard { unsigned long long from, count, total; };\n\n"
              "static void *worker(void *p)\n{\n"
              "    struct shard *s = p;\n"
              "    s->total = 0;\n"
              "    run(s->from, s->count, &s->total);\n"
              "    return 0;\n"
              "}\n\n"
              "int main(int argc, char **argv)\n{\n", o);
        if (match)
            fputs("    if (argc < 2) { fprintf(stderr, \"usage: %s TARGETFILE [jobs]\\n\", argv[0]); return 2; }\n"
                  "    if (rt_load(&TB, argv[1])) { fprintf(stderr, \"rxejit: cannot read %s\\n\", argv[1]); return 2; }\n"
                  "    int argoff = 2;\n", o);
        else
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
              "        sh[t].count = base + ((unsigned long long)t < rem ? 1 : 0);\n"
              "        off += sh[t].count;\n"
              "    }\n"
              "    for (int t = 1; t < T; t++) pthread_create(&tid[t], 0, worker, &sh[t]);\n"
              "    worker(&sh[0]);\n"
              "    for (int t = 1; t < T; t++) pthread_join(tid[t], 0);\n"
              "    unsigned long long total = 0;\n"
              "    for (int t = 0; t < T; t++) total += sh[t].total;\n", o);
        fputs(match
              ? "    fprintf(stderr, \"%llu matches\\n\", total);\n    rt_set_free(&TB);\n"
              : "    printf(\"%llu\\n\", total);\n", o);
        fputs("    return 0;\n}\n", o);
    } else if (match) {
        // N over 64 bits: unsplittable, so one thread (the mutex uncontended).
        fputs("int main(int argc, char **argv)\n{\n"
              "    if (argc < 2) { fprintf(stderr, \"usage: %s TARGETFILE\\n\", argv[0]); return 2; }\n"
              "    if (rt_load(&TB, argv[1])) { fprintf(stderr, \"rxejit: cannot read %s\\n\", argv[1]); return 2; }\n"
              "    unsigned long long acc = 0;\n"
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
                           int sink, const char *nmemb, const char *jobs,
                           const char *matchfile, int verbose)
{
    char dir[] = "/tmp/rxejit.XXXXXX";
    if (!mkdtemp(dir)) { perror("rxejit: mkdtemp"); return 2; }

    char src[64], exe[64];
    snprintf(src, sizeof src, "%s/m.c", dir);
    snprintf(exe, sizeof exe, "%s/m", dir);

    int ret = 0;
    FILE *f = fopen(src, "w");
    if (!f) { perror("rxejit: fopen"); ret = 2; goto done; }
    emit(f, pattern, w, nw, sink, nmemb, verbose);
    fclose(f);

    const char *cc = getenv("CC");
    if (!cc || !*cc) cc = "cc";
    char *cargv[] = { (char *)cc, "-O2", "-pthread", src, "-o", exe, NULL };
    int rc = spawn(cargv);
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

int main(int argc, char **argv)
{
    const char *prog = argc > 0 ? argv[0] : "rxejit";
    int emit_only = 0, sink = SINK_WRITE, verbose = 0, opt;
    const char *jobs = NULL;              // thread count, forwarded to the exe
    const char *matchfile = NULL;         // target file for -m

    while ((opt = getopt(argc, argv, "Sndvj:m:h")) != -1) {
        switch (opt) {
            case 'S': emit_only = 1; break;
            case 'n': sink = SINK_COUNT; break;
            case 'd': sink = SINK_DUP; break;
            case 'v': verbose = 1; break;
            case 'j': jobs = optarg; break;
            case 'm': sink = SINK_MATCH; matchfile = optarg; break;
            case 'h':
            default:
                fprintf(stderr,
"usage: %s [-S] [-n | -m file | -d [-v]] [-j jobs] REGEX\n"
"  Compile the set REGEX describes into C and run it, enumerating the members.\n"
"  Handles a fixed-width mask, and alternations of equal-length branches; other\n"
"  patterns are declined with a reason.\n"
"    -S       print the generated C to stdout instead of compiling and running it.\n"
"    -n       count the members rather than print them (times the walk, no I/O).\n"
"    -m file  print only the members present in 'file' (one target per line):\n"
"             the mask is a keyspace, 'file' the set to sift it against.\n"
"    -d       report duplicate members: hash each into a per-thread set and\n"
"             merge at the join. Exit 0 if all distinct, 1 if a duplicate.\n"
"    -v       with -d, list the repeated members and their counts.\n"
"    -j jobs  threads for -n and -d (default: one per CPU). Printing stays\n"
"             single-threaded and ordered.\n",
                    prog);
                return opt == 'h' ? 0 : 2;
        }
    }
    if (optind != argc - 1) {
        fprintf(stderr, "usage: %s [-S] [-n | -m file | -d [-v]] [-j jobs] REGEX\n", prog);
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

    struct build b;
    b.w = malloc(MAXW * sizeof *b.w);
    if (!b.w) { fprintf(stderr, "%s: out of memory\n", prog); rxe_free(rxe); return 2; }

    int nw = collect(&b, rxe);
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
        for (int i = 0; i < nw; i++) mpz_mul_ui(N, N, (unsigned long)b.w[i].n);
        char nbuf[32];
        const char *nmemb = NULL;
        if (mpz_fits_ulong_p(N)) { gmp_snprintf(nbuf, sizeof nbuf, "%Zu", N); nmemb = nbuf; }

        if (emit_only) { emit(stdout, pattern, b.w, nw, sink, nmemb, verbose); ret = 0; }
        else           ret = compile_and_run(pattern, b.w, nw, sink, nmemb, jobs, matchfile, verbose);
        mpz_clear(N);
    }

    free_build(&b);
    free(b.w);
    rxe_free(rxe);
    return ret;
}
