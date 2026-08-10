/*
 * Compile-and-run check of the public library API.
 *
 * tests/run.sh drives the rxenum binary. This links against librxe.a directly,
 * so it covers the part a library consumer actually touches, and it fails to
 * compile if rxe.h drifts out of step with the library.
 *
 * The first case is the reason this file exists: rxe_parse() used to write a
 * NUL over the '}' of a repetition and restore it afterwards, so handing it a
 * string literal -- the most natural thing any caller does -- segfaulted.
 */

#include <stdio.h>
#include <string.h>
#include "rxe.h"
#include "lens.h"

static int failures = 0;

static void check(const char *what, const char *want, const char *got)
{
    if (strcmp(want, got) == 0) return;
    printf("FAIL  %s\n        expected: %s\n        got:      %s\n", what, want, got);
    failures++;
}

static void check_int(const char *what, long want, long got)
{
    char w[32], g[32];
    sprintf(w, "%ld", want);
    sprintf(g, "%ld", got);
    check(what, w, g);
}

// Walks the whole set, joining members with '/' so empty ones stay visible.
static void collect(struct rxe *rxe, char *out, size_t outsz)
{
    char item[128];
    mpz_t zero;
    mpz_init(zero);
    rxe_seek(rxe, zero);
    mpz_clear(zero);
    out[0] = 0;
    do {
        rxe_current(item, sizeof(item) - 1, rxe);
        if (strlen(out) + strlen(item) + 2 < outsz) {
            strcat(out, item);
            strcat(out, "/");
        }
    } while (rxe_next(rxe));
}

int main(void)
{
    char buf[256];

    // 1. A string literal must survive being parsed.
    struct rxe *rxe = rxe_parse("a{2,3}b", 0);
    check_int("literal input parses without error", RXE_OK, rxe_error(rxe));
    gmp_sprintf(buf, "%Zd", rxe->nitems);
    check("cardinality of a{2,3}b", "2", buf);
    rxe_free(rxe);

    // 2. The caller's buffer must come back untouched.
    char writable[] = "a{2,3}b";
    rxe = rxe_parse(writable, 0);
    check("caller's buffer is not modified", "a{2,3}b", writable);
    rxe_free(rxe);

    // 3. Enumeration through the public entry points.
    rxe = rxe_parse("[ab][cd]", 0);
    collect(rxe, buf, sizeof(buf));
    check("enumerating [ab][cd]", "ac/ad/bc/bd/", buf);
    rxe_free(rxe);

    // 4. Random access agrees with the enumeration order.
    rxe = rxe_parse("[ab][cd]", 0);
    mpz_t pos;
    mpz_init_set_ui(pos, 2);
    check_int("seek to index 2 succeeds", 0, rxe_seek(rxe, pos));
    rxe_current(buf, sizeof(buf) - 1, rxe);
    check("element at index 2", "bc", buf);
    mpz_set_ui(pos, 99);
    check_int("seek past the end reports failure", 1, rxe_seek(rxe, pos));
    mpz_clear(pos);
    rxe_free(rxe);

    // 5. Errors are reported, not crashed on. rxe_error_message() indexes a
    //    table with rxe->status, which rxe_new() once left uninitialised.
    rxe = rxe_parse("a{3,1}", 0);
    check_int("a{3,1} is rejected", RXE_BAD_REPETITION, rxe_error(rxe));
    check("its message", "bad repetition parameters", rxe_error_message(rxe));
    rxe_free(rxe);

    rxe = rxe_parse("abc", 0);
    check_int("a valid regex reports RXE_OK", RXE_OK, rxe_error(rxe));
    check("and an empty message", "", rxe_error_message(rxe));
    rxe_free(rxe);

    // 6. Flags reach the parser.
    rxe = rxe_parse("a", RXE_CASELESS);
    gmp_sprintf(buf, "%Zd", rxe->nitems);
    check("RXE_CASELESS doubles a letter", "2", buf);
    rxe_free(rxe);

    rxe = rxe_parse(".", RXE_DOTALL);
    gmp_sprintf(buf, "%Zd", rxe->nitems);
    check("RXE_DOTALL admits all 256 bytes", "256", buf);
    rxe_free(rxe);

    // 7. The keyed permutation. It must be a bijection on [0,N): feeding it
    //    every index in range has to give back every index in range, once.
    //    Note this runs before any rxe_parse in a fresh process would have
    //    initialised the allocator, which is deliberate -- rxe_permutation_new
    //    used to segfault when it was the first entry point called.
    {
        unsigned long n = 1000, k;
        mpz_t dom, i, out;
        mpz_init_set_ui(dom, n);
        mpz_init(i);
        mpz_init(out);
        struct rxe_permutation *perm = rxe_permutation_new(dom, "a key");
        char *seen = calloc(n, 1);
        unsigned long dup = 0, oor = 0, missing = 0;
        for (k = 0; k < n; k++) {
            mpz_set_ui(i, k);
            rxe_permutation_map(out, perm, i);
            if (mpz_cmp_ui(out, n) >= 0) { oor++; continue; }
            if (seen[mpz_get_ui(out)]++) dup++;
        }
        for (k = 0; k < n; k++) if (!seen[k]) missing++;
        check_int("permutation stays in range", 0, oor);
        check_int("permutation repeats nothing", 0, dup);
        check_int("permutation misses nothing", 0, missing);
        free(seen);
        rxe_permutation_free(perm);
        // A null permutation is the identity, so callers need no special case.
        mpz_set_ui(i, 42);
        rxe_permutation_map(out, NULL, i);
        check_int("a null permutation is the identity", 42, mpz_get_ui(out));
        // Out of contract but must not hang: an index past the domain has no
        // image, so the map returns it unchanged rather than cycle-walking a
        // value the set does not contain. The boundary index (== domain) is the
        // dangerous one -- it can be a fixed point of the Feistel and once spun
        // forever. If the guard regresses, this test times out rather than
        // reporting, which is the point.
        {
            mpz_t small;
            mpz_init_set_ui(small, 3);
            struct rxe_permutation *sp = rxe_permutation_new(small, "k");
            mpz_set_ui(i, 50);
            rxe_permutation_map(out, sp, i);
            check_int("an out-of-range index is returned unchanged", 50,
                      (int)mpz_get_ui(out));
            mpz_set_ui(i, 3);
            rxe_permutation_map(out, sp, i);
            check_int("the boundary index does not hang", 3, (int)mpz_get_ui(out));
            rxe_permutation_free(sp);
            mpz_clear(small);
        }
        mpz_clear(dom); mpz_clear(i); mpz_clear(out);
    }

    // 8. Counted repetition. The point of holding a repetition as a count
    //    rather than as one copy per position is that the memory it costs
    //    stops depending on the repeat count, so the test is a size that
    //    could not previously be parsed at all: writing [a-z]{1,20000} out
    //    wanted about 26GB.
    {
        struct rxe *rxe = rxe_parse("[a-z]{1,20000}", 0);
        check_int("a 20000-wide repetition parses", RXE_OK, rxe_error(rxe));
        // sum(26^j, j=1..20000) has 28300 decimal digits.
        check_int("its cardinality has 28300 digits", 28300,
                  (long)mpz_sizeinbase(rxe->nitems, 10));
        char buf[64];
        mpz_t pos;
        // Index 27 is the second string of the two-character block, which
        // starts at 26: a..z, then aa, ab.
        mpz_init_set_ui(pos, 27);
        check_int("seek into it succeeds", 0, rxe_seek(rxe, pos));
        rxe_current(buf, sizeof(buf) - 1, rxe);
        check("and lands on the right element", "ab", buf);
        mpz_clear(pos);
        rxe_free(rxe);
    }

    // 9. rxe_deep_clone has to copy a repetition node, not just the
    //    subexpression under it. Recursion -- the (?N) construct -- is the
    //    only caller left, so this is where it gets exercised directly.
    {
        struct rxe *rxe = rxe_parse("([ab]{1,2})(?1)", 0);
        check_int("a repetition inside a recursed group parses", RXE_OK,
                  rxe_error(rxe));
        // Six strings in the group, squared: the clone must have the same
        // cardinality as the original rather than an empty or aliased one.
        check_int("the clone has the same cardinality as the original", 36,
                  (long)mpz_get_ui(rxe->nitems));
        rxe_free(rxe);
    }

    // 10. Sets with no largest member. rxe_is_infinite is the only way to
    //     tell: nitems counts the finite alternations, so for 'a*' it is zero
    //     and for 'a|b*' it is one, neither of which is the size of the set.
    {
        struct rxe *rxe = rxe_parse("a*", 0);
        char buf[64];
        mpz_t pos;
        check_int("a* parses", RXE_OK, rxe_error(rxe));
        check_int("a* is infinite", 1, rxe_is_infinite(rxe) != 0);
        mpz_init(pos);
        // Every index is valid, however large, so seek never runs off the end.
        mpz_set_ui(pos, 40);
        check_int("seeking far into it succeeds", 0, rxe_seek(rxe, pos));
        rxe_current(buf, sizeof(buf) - 1, rxe);
        check_int("and gives a run of that length", 40, (int)strlen(buf));
        // Iteration cannot carry out of an infinite set, so rxe_next stays
        // true however long it is driven.
        check_int("iterating past it never wraps", 1, rxe_next(rxe) ? 1 : 0);
        rxe_current(buf, sizeof(buf) - 1, rxe);
        check_int("and steps to the next length", 41, (int)strlen(buf));
        mpz_clear(pos);
        rxe_free(rxe);

        rxe = rxe_parse("abc", 0);
        check_int("a finite set is not infinite", 0, rxe_is_infinite(rxe));
        rxe_free(rxe);
    }

    // 11. Two unbounded quantifiers are two dimensions spread over the one
    //     index by a pairing function, which must be onto: every pair of
    //     lengths has to be reachable, or part of the set is unreachable.
    {
        struct rxe *rxe = rxe_parse("a*b*", 0);
        char buf[64];
        mpz_t pos;
        int i, seen[6][6];
        memset(seen, 0, sizeof(seen));
        mpz_init(pos);
        for (i = 0; i < 400; i++) {
            const char *p;
            int na = 0, nb = 0;
            mpz_set_ui(pos, i);
            check_int("seek into a*b* succeeds", 0, rxe_seek(rxe, pos));
            rxe_current(buf, sizeof(buf) - 1, rxe);
            for (p = buf; *p == 'a'; p++) na++;
            for (; *p == 'b'; p++) nb++;
            if (*p) { check("a*b* generated a non-member", "", buf); break; }
            if (na < 6 && nb < 6) seen[na][nb]++;
        }
        {
            int missing = 0, na, nb;
            for (na = 0; na < 6; na++)
                for (nb = 0; nb < 6; nb++)
                    if (!seen[na][nb]) missing++;
            check_int("every (a,b) pair up to 5 each is reached", 0, missing);
        }
        mpz_clear(pos);
        rxe_free(rxe);
    }

    // 12. Counting by length. rxe_count_at_length answers a question a
    //     cardinality cannot -- how many members are this long -- and it is
    //     what puts an infinite set in shortest-first order.
    {
        struct rxe *rxe = rxe_parse("(\\d+,)*", 0);
        mpz_t c;
        int L;
        // 1, 0, 10, 100, 1100: nothing of length one, ten one-digit lists,
        // a hundred two-digit ones, then a thousand three-digit lists plus a
        // hundred pairs of one-digit ones.
        long want[] = { 1, 0, 10, 100, 1100 };
        check_int("(\\d+,)* parses", RXE_OK, rxe_error(rxe));
        check_int("and is enumerated shortest first", 1,
                  rxe_is_shortlex(rxe) != 0);
        mpz_init(c);
        for (L = 0; L < 5; L++) {
            char what[64];
            rxe_count_at_length(c, rxe, L);
            sprintf(what, "(\\d+,)* has %ld members of length %d", want[L], L);
            check_int(what, want[L], (long)mpz_get_ui(c));
        }
        mpz_clear(c);
        rxe_free(rxe);
    }

    // 13. A backreference ties two positions' lengths together, which the
    //     convolution the counts are built from cannot express, so such an
    //     expression keeps the diagonal order rather than being refused.
    {
        struct rxe *rxe = rxe_parse("([ab]+)\\1", 0);
        char buf[64];
        mpz_t pos;
        check_int("a backreferencing infinite set still parses", RXE_OK,
                  rxe_error(rxe));
        check_int("it is infinite", 1, rxe_is_infinite(rxe) != 0);
        check_int("but not shortest first", 0, rxe_is_shortlex(rxe));
        mpz_init_set_ui(pos, 3);
        check_int("and is still fully addressable", 0, rxe_seek(rxe, pos));
        rxe_current(buf, sizeof(buf) - 1, rxe);
        check("giving a doubled string", "abab", buf);
        mpz_clear(pos);
        rxe_free(rxe);
    }

    // 14. Enumeration by length must not disturb a finite expression, whose
    //     order the documented radix conversion depends on.
    {
        struct rxe *rxe = rxe_parse("([0-9A-F]{4} ){2}", 0);
        char buf[64];
        mpz_t pos;
        check_int("a finite set is not shortest first", 0, rxe_is_shortlex(rxe));
        mpz_init_set_ui(pos, 3735928559UL);
        check_int("seek succeeds", 0, rxe_seek(rxe, pos));
        rxe_current(buf, sizeof(buf) - 1, rxe);
        check("place value still converts radix", "DEAD BEEF ", buf);
        mpz_clear(pos);
        rxe_free(rxe);
    }

    // 15. Registered dictionaries. This is the path the browser build uses:
    //     a caller registers words by name, the library keeps its own copy,
    //     and [:name:] draws from them. No file I/O is involved.
    {
        const char *animals[] = { "cat", "dog", "ferret" };
        struct rxe *rxe;
        char buf[64];
        mpz_t pos;
        rxe_register_dict("animals", animals, 3);
        rxe = rxe_parse("[:animals:]{2}", 0);
        check_int("a registered dictionary parses", RXE_OK, rxe_error(rxe));
        check_int("and is a product of its words", 9,
                  (int)mpz_get_ui(rxe->nitems));
        mpz_init_set_ui(pos, 5);          // dog then ferret: 1*3 + 2
        check_int("seek into it succeeds", 0, rxe_seek(rxe, pos));
        rxe_current(buf, sizeof(buf) - 1, rxe);
        check("giving the right phrase", "dogferret", buf);
        mpz_clear(pos);
        rxe_free(rxe);

        // A member longer than the caller's buffer is truncated, not
        // overrun: ask for one character of room.
        rxe = rxe_parse("[:animals:]", 0);
        mpz_init_set_ui(pos, 2);          // ferret
        rxe_seek(rxe, pos);
        mpz_clear(pos);
        rxe_current(buf, 3, rxe);
        check("a long word is truncated to fit", "fer", buf);
        rxe_free(rxe);

        // An unknown name is an error, not a crash.
        rxe = rxe_parse("[:nosuch:]", 0);
        check_int("an unknown dictionary is refused",
                  RXE_UNKNOWN_DICT, rxe_error(rxe));
        rxe_free(rxe);

        rxe_free_dicts();
    }

    {
        // Source spans: each node remembers the exact text it came from, so a
        // consumer can show the regex as typed rather than reconstruct it.
        struct rxe *rxe = rxe_parse("\\d[a-z]{2}", 0);
        char s[64];
        int n;
        check_int("a spanned pattern parses", RXE_OK, rxe_error(rxe));
        struct rxe_node *first = rxe->head->head;      // \d
        n = first->src_end - first->src_start;
        memcpy(s, rxe->source + first->src_start, n); s[n] = 0;
        check("the first node's span is the shorthand verbatim", "\\d", s);
        // A repeat wraps a body whose span is just the atom, not the quantifier.
        struct rxe_node *body = first->next->rxe->head->head;   // [a-z] inside {2}
        n = body->src_end - body->src_start;
        memcpy(s, rxe->source + body->src_start, n); s[n] = 0;
        check("the repeated body's span is the class alone", "[a-z]", s);
        rxe_free(rxe);
    }
    {
        // A subroutine points back at the group it copies, for drawings that
        // want to collapse the copy to a reference.
        struct rxe *rxe = rxe_parse("(a)(?1)", 0);
        char s[64];
        int n;
        check_int("a subroutine parses", RXE_OK, rxe_error(rxe));
        struct rxe_node *grp = rxe->head->head;        // (a)
        struct rxe_node *sub = grp->next;              // (?1)
        check_int("the subroutine refers to a group", 1, sub->refers_to != NULL);
        check_int("and it is exactly the group it names", 1,
                  sub->refers_to == grp->rxe);
        n = sub->src_end - sub->src_start;
        memcpy(s, rxe->source + sub->src_start, n); s[n] = 0;
        check("its span is the call text", "(?1)", s);
        rxe_free(rxe);
    }

    {
        // A parse error carries the offset it was found at, for a caret.
        struct rxe *rxe = rxe_parse("a{2,1}", 0);
        check_int("a bad repetition is refused", RXE_BAD_REPETITION, rxe_error(rxe));
        check_int("and the error sits on the brace", 1, rxe_error_pos(rxe));
        rxe_free(rxe);
        // An error inside a group reports where it really is, not the group.
        rxe = rxe_parse("ab(cd[ef)", 0);
        check_int("a nested error is refused", RXE_UNTERMINATED_CLASS,
                  rxe_error(rxe));
        check_int("and points inside the group", 5, rxe_error_pos(rxe));
        rxe_free(rxe);
    }

    printf("api: %s\n", failures ? "FAILURES ABOVE" : "all checks passed");
    return failures ? 1 : 0;
}
