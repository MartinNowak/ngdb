#include <stdio.h>
#include <unistd.h>

long long factorial(long long n)
{
    if (n == 0) {
	return 1;
    }
    return n * factorial(n - 1);
}

int main(int argc, char** argv)
{
    printf("factorial(10)=%d\n", (int) factorial(10));
}
