#include <stdio.h>

void bar(int argc, char** argv)
{
}

int
main(int argc, char** argv)
{
	int i;

	int func(int n)
	{
		bar(argc, argv);
		return n * i;
	}

	bar(argc, argv);
	for (i = 0; i < 10; i++) {
		int f = func(i);
		printf("func(%d) = %d\n", i, f);
	}
}
