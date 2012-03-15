
int main(void)
{
    int a[10],i, *p;
    for (i=0; i<10; i++){
        p = &a[i];
        *p = i+1;
        printf("p = 0x%08x, addr = 0x%08x, val=%d\n", p, &a[i], a[i]);
    }
    return 1;
}
