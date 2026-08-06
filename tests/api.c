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
    rxe = rxe_parse("a*", 0);
    check_int("a* is rejected", RXE_INFINITE, rxe_error(rxe));
    check("its message", "infinite", rxe_error_message(rxe));
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

    printf("api: %s\n", failures ? "FAILURES ABOVE" : "all checks passed");
    return failures ? 1 : 0;
}
