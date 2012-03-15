#include <stdio.h>

void
f(int a)
{
    int b, *p;

    b=a;
    a = a+10;
    p = &a;
    return;
}

int main(){
    int a;
    int *p;
    a = 10;
    f(a);
    p = &a;
}
