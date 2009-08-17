#include <stdio.h>

inline double
factorial(double n)
{
	if (n == 0)
		return 1;
	return n * factorial(n - 1);
}

int
main(int argc, char** argv)
{
	int i;

	for (i = 0; i < 10; i++) {
		double f = factorial(i);
		printf("factorial(%d) = %g\n", i, f);
	}
}
