all: rxenum

rxenum: rxenum.o librxe.a rxe.h
	$(CC) rxenum.o -g -L. -lgmp -lm -lrxe -o rxenum

rxenum.o: rxenum.c rxe.h

rxe.o: rxe.c rxe.h

rxe_alt.o: rxe_alt.c rxe_alt.h rxe.h

rxe_node.o: rxe_node.c rxe_node.h rxe.h

bkreftbl.o: bkreftbl.c bkreftbl.h rxe.h

parse.o: parse.c rxe_node.h rxe_alt.h rxe.h

librxe.a: rxe.o rxe_alt.o rxe_node.o parse.o bkreftbl.o
	$(AR) rv librxe.a rxe.o rxe_alt.o rxe_node.o parse.o bkreftbl.o

SRC = rxenum.c rxe.c rxe_alt.c rxe_node.c parse.c bkreftbl.c
HDR = rxe.h rxe_alt.h rxe_node.h bkreftbl.h
SANFLAGS = -g -O0 -fsanitize=address,undefined -fno-omit-frame-pointer

test: rxenum
	sh tests/run.sh
	@if command -v python3 >/dev/null 2>&1; then \
	    python3 tests/oracle.py; \
	else \
	    echo "oracle: skipped, python3 not found"; \
	fi

# Same suite under AddressSanitizer, UndefinedBehaviorSanitizer and
# LeakSanitizer. Leak detection is on: a leak here fails the build.
rxenum-asan: $(SRC) $(HDR)
	$(CC) $(SANFLAGS) $(SRC) -lgmp -lm -o rxenum-asan

test-asan: rxenum-asan
	ASAN_OPTIONS=detect_leaks=1 RXENUM=./rxenum-asan sh tests/run.sh
	@if command -v python3 >/dev/null 2>&1; then \
	    ASAN_OPTIONS=detect_leaks=1 RXENUM=./rxenum-asan python3 tests/oracle.py; \
	fi

clean:
	rm -f *~ *.o *.a rxenum rxenum-asan

install: rxenum
	install -m 755 rxenum /usr/bin
	install -m 644 rxenum.1 /usr/share/man/man1

.PHONY: all test test-asan clean install

