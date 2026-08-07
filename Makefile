PREFIX ?= /usr/local

SRC = rxenum.c rxe.c rxe_alt.c rxe_node.c parse.c bkreftbl.c permute.c repeat.c pair.c
HDR = rxe.h rxe_alt.h rxe_node.h parse.h bkreftbl.h repeat.h pair.h
WARNFLAGS = -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare
SANFLAGS = -g -O0 -fsanitize=address,undefined -fno-omit-frame-pointer

CFLAGS += $(WARNFLAGS)

all: rxenum

rxenum: rxenum.o librxe.a rxe.h
	$(CC) rxenum.o -g -L. -lgmp -lm -lrxe -o rxenum

rxenum.o: rxenum.c rxe.h

rxe.o: rxe.c rxe.h parse.h repeat.h pair.h

rxe_alt.o: rxe_alt.c rxe_alt.h rxe_node.h rxe.h

rxe_node.o: rxe_node.c rxe_node.h repeat.h rxe.h

bkreftbl.o: bkreftbl.c bkreftbl.h rxe.h

parse.o: parse.c parse.h rxe_node.h rxe_alt.h repeat.h rxe.h

permute.o: permute.c rxe.h

repeat.o: repeat.c repeat.h rxe.h

pair.o: pair.c pair.h rxe.h

librxe.a: rxe.o rxe_alt.o rxe_node.o parse.o bkreftbl.o permute.o repeat.o pair.o
	$(AR) rv librxe.a rxe.o rxe_alt.o rxe_node.o parse.o bkreftbl.o permute.o repeat.o pair.o

tests/api: tests/api.c librxe.a rxe.h
	$(CC) $(WARNFLAGS) -I. tests/api.c librxe.a -lgmp -lm -o tests/api

test: rxenum tests/api
	sh tests/run.sh
	./tests/api
	@if command -v python3 >/dev/null 2>&1; then \
	    python3 tests/oracle.py; \
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

test-asan: rxenum-asan tests/api-asan
	ASAN_OPTIONS=detect_leaks=1 RXENUM=./rxenum-asan sh tests/run.sh
	ASAN_OPTIONS=detect_leaks=1 ./tests/api-asan
	@if command -v python3 >/dev/null 2>&1; then \
	    ASAN_OPTIONS=detect_leaks=1 RXENUM=./rxenum-asan python3 tests/oracle.py; \
	fi

clean:
	rm -f *~ *.o *.a rxenum rxenum-asan tests/api tests/api-asan

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

.PHONY: all test test-asan clean install uninstall

