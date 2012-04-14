GCC=gcc
PLUGIN_SOURCE_FILES= lbc_malloc.c mallocinstr.c
PLUGIN_OBJECT_FILES= $(patsubst %.c,%.o,$(PLUGIN_SOURCE_FILES))
CFLAGS+= -I. -fPIC -O2 -g -c

all: lbc_hooks.so

lbc_hooks.so: $(PLUGIN_OBJECT_FILES)
	$(GCC) -shared $^ -o $@
