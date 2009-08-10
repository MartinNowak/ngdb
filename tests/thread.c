#include <stdio.h>
#include <stdint.h>
#include <pthread.h>
#include <unistd.h>

void* foo(void* arg)
{
	static __thread int n;
	int i;

	n = (int) (uintptr_t) arg;
	for (i = 0; i < 10; i++) {
		printf("%d: loop %d\n", n, i);
		sleep(1);
	}
}

int main(int argc, char** argv)
{
	int i;
	pthread_t t[10];

	for (i = 0; i < 10; i++)
		pthread_create(&t[i], NULL, foo, (void*) i);
	for (i = 0; i < 10; i++)
		pthread_join(t[i], NULL);
}
