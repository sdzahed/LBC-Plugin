struct A
{
    int mema;
    int memarray[10];
};

void main(void)
{
    struct A a;
    int *p, b;

    p = a.memarray;
    b = *p + 1;
}
