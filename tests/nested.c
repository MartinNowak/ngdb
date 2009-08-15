#include <stdio.h>

int
main(int argc, char** argv)
{
	int i;

	int func(int n)
	{
		return n * i;
	}

	for (i = 0; i < 10; i++) {
		int f = func(i);
		printf("func(%d) = %d\n", i, f);
	}
}
