#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

void main(void)
{
	char *buf;
	int i;

	printf("Allocating mem..\n");
	buf = (char *) malloc (100);

	for (i=0; i < 100; i++)
		buf[i]=i;

    buf = (char *) realloc (buf, 200);
	for (i=0; i < 100; i++)
		assert(buf[i] == i);

	printf("Freeing mem..\n");
	free(buf);
}
