
int main(void)
{
    int a[10][20][30], b;
    int *p1;

    b = 5;
    p1 = a;
    p1 = &a[b+1][b+2][b+2];

    b = a[b+11][b+2][b+3];
}
