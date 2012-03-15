#include<stdio.h>

//extern int f(int) __attribute__((always_inline));
//int g(int) __attribute__((always_inline));

int g(int a)
{
    return a;
}

struct A{
    int mema;
};

int main()
{
    struct A s_a;
	int a=5;
	int *p;
	a=10;
    s_a.mema = 10;
	p = &(s_a.mema);
    a = p[0] + g(a);
	return 0;
}
