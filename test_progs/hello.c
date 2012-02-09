#include<stdio.h>
int main()
{
	int a=5;
	int *p;
	a=10;
	p = &a;
    a = p[0] + 1;
	return 0;
}
