
int main(void)
{
    int a[10], b;
    int *p1, **p2, i;

    for(i=0;i<10;i++)
        a[i]=i+1;

    p1 = a;
    p2 = &p1;

    b = *p1 + 10; // 11
    printf("b11 = %d\n", b);
    b = p1[5] + 10; // 16
    printf("b16 = %d\n", b);
    b = a[1] + 10; // 12
    printf("b12 = %d\n", b);
    b = (*p2)[8]; // 9
    printf("b9 = %d\n", b);

    for(i=0;i<10;i++)
        printf("%3d\n", a[i]);
    return 1;
}
