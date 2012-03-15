struct A {int mema;};
struct B{struct A bmema;int bmemb;};
int main(void)
{
    struct A a1;
    struct B b1;
    int a2[10][10];
    int a3[10];
    //struct A *p1;
    int *p2;

    //p2 = &a2[2][2];
    //p2 = &b1.bmema.mema;
    p2 = a3;
}
