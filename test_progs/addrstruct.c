#include<stdio.h>


struct A{
    int mema;
    int memarr[10];
};

int main()
{
    struct A s_a;
	int *p;
    s_a.mema = 10;
	p = s_a.memarr;
    s_a.mema = p[0];
	return 0;
}
