struct A
{
    int mema;
    int memarray[10];
};

void main(void)
{
    struct A a;
    int *p, b, i;
    for(i=0; i< 10; i++)
        a.memarray[i]=i;
    p = a.memarray;
    b = *p + 1;
    printf("b = %d (1)\n", b);
}
