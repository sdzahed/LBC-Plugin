CC=gcc
RM=rm
PLUGIN_SOURCE_FILES= plugin_lbc.c
PLUGIN_OBJECT_FILES= $(patsubst %.c,%.o,$(PLUGIN_SOURCE_FILES))
GCCPLUGINS_DIR:= $(shell $(CC) -print-file-name=plugin)
CFLAGS+= -DLBCDEBUG -I$(GCCPLUGINS_DIR)/include -I../judy-1.0.5/src -fPIC -O2 -g -c

all: plugin_lbc.so

plugin_lbc.so: $(PLUGIN_OBJECT_FILES)
	$(CC) -shared $^ -o $@ -lJudy -L.

