struct A
{
    int mema;
    int memarray[10];
};

void main(void)
{
    struct A a;
    int *p, b;
    p = &a.mema;
    a.mema = 10;
    b = *p + 10;
    printf("*p = %d (==10?), mema=%d (==10?) b=%d (==20?)\n", *p, a.mema, b);
}
