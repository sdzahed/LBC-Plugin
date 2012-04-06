#include <stdio.h>

void print_num(int *p)
{
    printf("Value at 0x%08x is %d\n", p, *p);
}

int main(void)
{
    int i = 10;
    print_num(&i);
    return 0;
}
