struct A
{
    int mema;
    int memarray[10];
};

void main(void)
{
    struct A a, *p;
    int b;
    a.mema=10;
    p = &a;
    b = (*p).mema + 10;
    printf (" b = %d(20)\n", b);
    b = p->mema + 10;
    printf (" b = %d(20)\n", b);
}
