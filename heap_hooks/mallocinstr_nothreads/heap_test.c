#include <stdio.h>
#include <stdlib.h>


void main(void)
{
    char *addr;
    int i;
    printf("Allocating mem...\n");
    addr = (char *) malloc (100);
    for ( i = 0; i<100; i++)
        addr[i] = i;
    printf("Freeing mem...\n");
    free(addr);
}
