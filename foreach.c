/*
 * librxe - a library for enumerating sets described by regexes, version 1.1.0
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

/*
 * foreach -- the enumeration driver a bruteforcer wants. rxenum grew its own
 * copy of this loop long ago; this lifts the shape into the library so any
 * consumer -- a keycracker, a candidate generator, a duplicate check -- gets
 * the fast walk without rewriting it, and so the eventual JIT has one reference
 * to agree with.
 *
 * The design point is that seek and step are different costs. rxe_seek turns an
 * index into a member by mixed-radix division, once per call; rxe_iterate steps
 * the odometer to the next member by carry, which is cheap and amortises to
 * nothing. So this seeks exactly once, to reach 'from', and steps for every
 * member after. A keyed shuffle cannot be walked this way -- consecutive output
 * positions scatter across the set, so each is a fresh seek -- and is left to
 * rxenum's own loop; foreach is the unshuffled fast path on purpose.
 *
 * It touches neither rxe_current nor rxe_iterate: it only drives them. That
 * keeps the primitive orthogonal to the engine it stands on, which is the whole
 * point of carving it out.
 */

#include "rxe.h"

int rxe_foreach(struct rxe *rxe, const mpz_t from, const mpz_t count,
                int maxlen, rxe_sink emit, void *ctx)
{
    if (!rxe || maxlen < 1) return RXE_FOREACH_RANGE;

    // One byte over the width, so a member of exactly 'maxlen' bytes fits whole
    // and one of maxlen+1 spills into the extra byte -- which is how a member
    // too long to render is told apart from one that just fills the width. The
    // sink is never handed a truncated member.
    char *str = malloc((size_t)maxlen + 2);
    if (!str) return RXE_FOREACH_TOOBIG;

    // idx is the absolute index handed to the sink and stepped alongside the
    // odometer; left is the countdown for 'count', held apart so a zero count
    // (no limit) never decrements and so never reaches the stop. Both are
    // copies: the arguments are const, and rxe_seek wants a mutable index.
    mpz_t idx, left;
    mpz_init_set(idx, from);
    mpz_init_set(left, count);

    int rc;

    // Seek once. A failure here is either an index past the end of a finite set
    // or a member too large to build even in principle; the overflow latch,
    // read and cleared, tells the two apart. rxe_check_overflow also clears any
    // stale latch before the walk, so the per-member test below is honest.
    rxe_check_overflow();
    if (rxe_seek(rxe, idx)) {
        rc = rxe_member_overflow ? RXE_FOREACH_TOOBIG : RXE_FOREACH_RANGE;
        rxe_member_overflow = 0;
        goto done;
    }

    for (;;) {
        char *end = rxe_current(str, maxlen + 1, rxe);
        size_t len = (size_t)(end - str);
        // Two ways a member cannot be delivered whole: the render path raised
        // the overflow latch on a closed-form repeat too big to build, or the
        // rendered member ran past the width and would reach the sink cut short.
        // Either stops the walk rather than passing off a stub.
        if (rxe_member_overflow) { rxe_member_overflow = 0; rc = RXE_FOREACH_TOOBIG; break; }
        if (len > (size_t)maxlen)                { rc = RXE_FOREACH_TOOBIG; break; }
        if (emit && emit(str, len, idx, ctx)) {
            rc = RXE_FOREACH_STOP;
            break;
        }
        // Meet the count before stepping, so exactly 'count' members are seen
        // and the odometer is not advanced past the last wanted one.
        if (mpz_sgn(left)) {
            mpz_sub_ui(left, left, 1);
            if (!mpz_sgn(left)) { rc = RXE_FOREACH_END; break; }
        }
        mpz_add_ui(idx, idx, 1);
        // A finite set wraps here -- rxe_iterate carries out and resets to the
        // first member -- which is the natural end. An infinite set never
        // wraps; only the count or the sink stops it.
        if (!rxe_next(rxe)) { rc = RXE_FOREACH_END; break; }
    }

done:
    mpz_clear(idx);
    mpz_clear(left);
    free(str);
    return rc;
}
