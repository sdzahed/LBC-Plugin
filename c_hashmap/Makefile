GCC=gcc
RM=rm
AR=ar
PLUGIN_SOURCE_FILES= hashmap.c
PLUGIN_OBJECT_FILES= $(patsubst %.c,%.o,$(PLUGIN_SOURCE_FILES))
CFLAGS+= -O2 -g -c

all: libhmap.a

hashmap.o: $(PLUGIN_SOURCE_FILES)
	$(GCC) $(CFLAGS) $^ -o $@

libhmap.a: $(PLUGIN_OBJECT_FILES)
	$(AR) rcs $@ $^

clean:
	$(RM) libhmap.a hashmap.o
