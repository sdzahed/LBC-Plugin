struct A
{
    int mema;
    int memarray[10];
};

struct B
{
    int memb;
    struct A a;
};

void main(void)
{
    struct A a;
    struct B b;
    int c;

    b.a = a;
    c = b.a.mema;
}
