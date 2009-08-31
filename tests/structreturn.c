#include <stdio.h>
#include <unistd.h>

struct A
{
    int a1;
    int a2;
    //char stuff[10];
};

struct A
foo(int n)
{
    struct A a;
    a.a1 = n;
    a.a2 = n + 1;
    return a;
}

int main(int argc, char** argv)
{
    struct A a = foo(argc);
    printf("a.a1=%d, a.a2=%d\n", a.a1, a.a2);
}
