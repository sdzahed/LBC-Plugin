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
    int c, *p;
    p2 = &b;
    b.a_ptr = &a;
    c = b.a.mema;
    c = b.a_ptr->mema;
    c = b.a.memarray[5];
    c = b.a_ptr->memarray[5];
    p = b.a.memarray;
    p = b.a_ptr->memarray;
    p = p2->a.memarray;
    p = p2->a_ptr->memarray;
}
