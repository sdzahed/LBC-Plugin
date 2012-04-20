CC=gcc
RM=rm
LIBLBC_SOURCE_FILES= zinit.c zcheck.h
LIBLBC_OBJECT_FILES= zinit.o liblbc.a
CFLAGS+= -DLBCDEBUG -I. -O2 -g -c

all: liblbc.a


liblbc.a: zinit.o
	ar rcs liblbc.a zinit.o


zinit.o: $(LIBLBC_SOURCE_FILES)
	$(CC) $(CFLAGS) zinit.c -o zinit.o

clean:
	$(RM) $(LIBLBC_OBJECT_FILES)

