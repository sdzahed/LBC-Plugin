GCC=gcc
PLUGIN_SOURCE_FILES= plugin_lbc.c
PLUGIN_OBJECT_FILES= $(patsubst %.c,%.o,$(PLUGIN_SOURCE_FILES))
GCCPLUGINS_DIR:= $(shell $(GCC) -print-file-name=plugin)
CFLAGS+= -I$(GCCPLUGINS_DIR)/include -fPIC -O2 -g -c

all: plugin_lbc.so

plugin_lbc.so: $(PLUGIN_OBJECT_FILES)
	$(GCC) -shared $^ -o $@
