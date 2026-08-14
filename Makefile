PREFIX ?= /usr/local

SRC = rxenum.c rxe.c rxe_alt.c rxe_node.c parse.c bkreftbl.c permute.c repeat.c comb.c pair.c lens.c dict.c rank.c graph.c foreach.c
HDR = rxe.h rxe_alt.h rxe_node.h parse.h bkreftbl.h repeat.h comb.h pair.h lens.h dict.h rxe_graph.h
WARNFLAGS = -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare
SANFLAGS = -g -O0 -fsanitize=address,undefined -fno-omit-frame-pointer

CFLAGS += $(WARNFLAGS)

all: rxenum

rxenum: rxenum.o librxe.a rxe.h
	$(CC) rxenum.o -g -L. -lgmp -lm -lrxe -o rxenum

# A sibling tool: draws the parse tree as Graphviz DOT. Not built by 'all'
# since it is only useful with graphviz on hand; 'make rxedot' when wanted.
rxedot: rxedot.o librxe.a rxe.h
	$(CC) rxedot.o -g -L. -lgmp -lm -lrxe -o rxedot

rxedot.o: rxedot.c rxe.h rxe_graph.h

# A sibling tool: rank, the inverse of rxenum -- given a string, print the
# index (or indices) at which it sits in the set. Not built by 'all'.
rxerank: rxerank.o librxe.a rxe.h
	$(CC) rxerank.o -g -L. -lgmp -lm -lrxe -o rxerank

rxerank.o: rxerank.c rxe.h

# A sibling tool: brute-force duplicate detection. Walks the set through
# rxe_foreach, hashing each member, and reports repeats. Not built by 'all'.
rxedup: rxedup.o librxe.a rxe.h
	$(CC) rxedup.o -g -L. -lgmp -lm -lrxe -lpthread -o rxedup

rxedup.o: rxedup.c rxe.h

rxenum.o: rxenum.c rxe.h

rxe.o: rxe.c rxe.h parse.h repeat.h pair.h lens.h

rxe_alt.o: rxe_alt.c rxe_alt.h rxe_node.h rxe.h

rxe_node.o: rxe_node.c rxe_node.h repeat.h rxe.h

bkreftbl.o: bkreftbl.c bkreftbl.h rxe.h

parse.o: parse.c parse.h rxe_node.h rxe_alt.h repeat.h dict.h rxe.h

permute.o: permute.c rxe.h

repeat.o: repeat.c repeat.h rxe.h
comb.o: comb.c comb.h repeat.h rxe.h

pair.o: pair.c pair.h rxe.h

lens.o: lens.c lens.h repeat.h rxe_alt.h rxe.h

dict.o: dict.c dict.h rxe.h

rank.o: rank.c rxe.h

graph.o: graph.c rxe.h rxe_graph.h

foreach.o: foreach.c rxe.h

librxe.a: rxe.o rxe_alt.o rxe_node.o parse.o bkreftbl.o permute.o repeat.o comb.o pair.o lens.o dict.o rank.o graph.o foreach.o
	$(AR) rv librxe.a rxe.o rxe_alt.o rxe_node.o parse.o bkreftbl.o permute.o repeat.o comb.o pair.o lens.o dict.o rank.o graph.o foreach.o

tests/api: tests/api.c librxe.a rxe.h
	$(CC) $(WARNFLAGS) -I. tests/api.c librxe.a -lgmp -lm -o tests/api

test: rxenum rxerank tests/api
	sh tests/run.sh
	./tests/api
	@if command -v python3 >/dev/null 2>&1; then \
	    python3 tests/oracle.py && python3 tests/shortlex.py && python3 tests/rank.py; \
	else \
	    echo "oracle: skipped, python3 not found"; \
	fi

# Same suite under AddressSanitizer, UndefinedBehaviorSanitizer and
# LeakSanitizer. Leak detection is on: a leak here fails the build.
rxenum-asan: $(SRC) $(HDR)
	$(CC) $(WARNFLAGS) $(SANFLAGS) $(SRC) -lgmp -lm -o rxenum-asan

tests/api-asan: tests/api.c $(filter-out rxenum.c,$(SRC)) $(HDR)
	$(CC) $(WARNFLAGS) $(SANFLAGS) -I. tests/api.c \
	    $(filter-out rxenum.c,$(SRC)) -lgmp -lm -o tests/api-asan

rxerank-asan: rxerank.c $(filter-out rxenum.c,$(SRC)) $(HDR)
	$(CC) $(WARNFLAGS) $(SANFLAGS) rxerank.c \
	    $(filter-out rxenum.c,$(SRC)) -lgmp -lm -o rxerank-asan

rxedup-asan: rxedup.c $(filter-out rxenum.c,$(SRC)) $(HDR)
	$(CC) $(WARNFLAGS) $(SANFLAGS) rxedup.c \
	    $(filter-out rxenum.c,$(SRC)) -lgmp -lm -lpthread -o rxedup-asan

test-asan: rxenum-asan rxerank-asan tests/api-asan
	ASAN_OPTIONS=detect_leaks=1 RXENUM=./rxenum-asan sh tests/run.sh
	ASAN_OPTIONS=detect_leaks=1 ./tests/api-asan
	@if command -v python3 >/dev/null 2>&1; then \
	    ASAN_OPTIONS=detect_leaks=1 RXENUM=./rxenum-asan python3 tests/oracle.py && \
	    ASAN_OPTIONS=detect_leaks=1 RXENUM=./rxenum-asan python3 tests/shortlex.py && \
	    ASAN_OPTIONS=detect_leaks=1 RXENUM=./rxenum-asan RXERANK=./rxerank-asan \
	        python3 tests/rank.py; \
	fi

# A speed comparison of rxedup against rxenum piped into a deduper. Not a test
# (nothing here passes or fails); just numbers. See tests/bench.sh.
bench: rxenum rxedup
	RXENUM=./rxenum RXEDUP=./rxedup bash tests/bench.sh

clean:
	rm -f *~ *.o *.a rxenum rxenum-asan rxedot rxedot-asan rxerank rxerank-asan rxedup rxedup-asan tests/api tests/api-asan

# librxe.a and rxe.h are installed too: the library is the deliverable, and
# until now only the demo program and its manual page were ever installed.
# Override PREFIX to relocate, DESTDIR to stage into a package root.
install: rxenum librxe.a
	install -d $(DESTDIR)$(PREFIX)/bin
	install -d $(DESTDIR)$(PREFIX)/lib
	install -d $(DESTDIR)$(PREFIX)/include
	install -d $(DESTDIR)$(PREFIX)/share/man/man1
	install -m 755 rxenum    $(DESTDIR)$(PREFIX)/bin
	install -m 644 librxe.a  $(DESTDIR)$(PREFIX)/lib
	install -m 644 rxe.h     $(DESTDIR)$(PREFIX)/include
	install -m 644 rxenum.1  $(DESTDIR)$(PREFIX)/share/man/man1

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/rxenum
	rm -f $(DESTDIR)$(PREFIX)/lib/librxe.a
	rm -f $(DESTDIR)$(PREFIX)/include/rxe.h
	rm -f $(DESTDIR)$(PREFIX)/share/man/man1/rxenum.1

.PHONY: all test test-asan bench clean install uninstall

