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
    b = p->memarray[6] + 10;
}
