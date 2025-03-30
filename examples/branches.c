#include <stdio.h>
#include <stdlib.h>

int func(int x, int y) {
	if (x <= 10)
		return 1;
	if (y > 5)
		return 2;
	return x + y;
}

int main(int argc, char* argv[]) {
	if (argc < 2)
		return -1;

	int x = atoi(argv[1]);
	int y = atoi(argv[2]);
	printf("%d %d %d\n", x, y, func(x, y));
}
