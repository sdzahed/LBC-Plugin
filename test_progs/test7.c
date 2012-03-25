struct A
{
    int mema;
    int memarray[10];
};

struct B
{
    int memb;
    struct A a;
    struct A *a_ptr;
    struct B *b;
};

void main(void)
{
    struct A a, *p1;
    struct B b, *p2;
    int c, *p, i;
    a.mema = 100;
    for( i=0; i<10; i++)
        a.memarray[i] = i;
    b.a = a;
    p2 = &b;
    b.a_ptr = &a;
    c = b.a.mema;
    printf ("c = %d (100)\n", c);
    c = b.a_ptr->mema;
    printf ("c = %d (100)\n", c);
    c = b.a.memarray[5];
    printf ("c = %d (5)\n", c);
    c = b.a_ptr->memarray[5];
    printf ("c = %d (5)\n", c);
    p = b.a.memarray;
    printf ("p[5] = %d (5)\n", p[5]);
    p = b.a_ptr->memarray;
    printf ("p[5] = %d (5)\n", p[5]);
    p = p2->a.memarray;
    printf ("p[5] = %d (5)\n", p[5]);
    p = p2->a_ptr->memarray;
    printf ("p[5] = %d (5)\n", p[5]);
}
