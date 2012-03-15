struct A
{
    int mema;
    int memarray[10];
};

void main(void)
{
    struct A a, *p;
    int b;
    p = &a;
    b = (*p).mema + 10;
    b = p->mema + 10;
}
