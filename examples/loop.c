int test(int x) {
    int i;
    int y = x;
    for (i = 0; i < 2 * x; i++) {
        y += 1;
    }

    return y + i;
}

#include <stdio.h>

int main () {
    printf("%d\n", test(2));
}
