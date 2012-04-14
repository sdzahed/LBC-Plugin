
SRC = hashtable.c mallocinstr.c
CC = gcc
CFLAGS = -O2 -Wall

libmallocinstr.so: hashtable.o mallocinstr.o
	${CC} ${CFLAGS} -shared -Wl,-soname,libmallocinstr.so -o libmallocinstr.so hashtable.o mallocinstr.o -lpthread

hashtable.o: hashtable.c common.h
	${CC} ${CFLAGS} -c -o hashtable.o -I . hashtable.c

mallocinstr.o: mallocinstr.c common.h
	${CC} ${CFLAGS} -c -o mallocinstr.o -I . mallocinstr.c

clean:
	rm -rf libmallocinstr.so *.o
