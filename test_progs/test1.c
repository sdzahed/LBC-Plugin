
int main(void)
{
    int a,b,c;
    int *p1,*p2;
    a = 10;
    p1 = &a;
    p2 = &a;
    b = *p1 + 10;
    c = p2[0] + 20;
    printf("a= %d, b=%d c=%d\n", a, b,c);
    return 1;
}
