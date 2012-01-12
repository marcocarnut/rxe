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

clean:
	rm -f *~ *.o *.a rxenum

install: rxenum
	install -m 755 rxenum /usr/bin
	install -m 644 rxenum.1 /usr/share/man/man1

