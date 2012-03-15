int f(int) __attribute__((always_inline));

inline int
f(int a)
{
    int b, *p;

    b=a;
    a = a+10;
    p = &a;
    return a;
}

