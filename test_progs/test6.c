struct A
{
    int mema;
    int memarray[10];
};

void main(void)
{
    struct A a, *p;
    int b, i;
    for( i=0; i<10; i++ )
        a.memarray[i] = i;
    p = &a;
    b = p->memarray[6] + 10;
    printf ("b = %d (16)\n", b);
}
