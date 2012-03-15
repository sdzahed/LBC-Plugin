#include <stdio.h>

int main(void)
{
	int i = 0;
    int test_array[5];
	for (i=-2;i<11;i++) {
        printf("test_array[%d]\n", i);
		test_array[i] = i;
	}
	return 0;
}
