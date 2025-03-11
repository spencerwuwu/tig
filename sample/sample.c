
void process_str_int(char*, int*);

int if_else(char *ptr, int a) {
    if (a > 0) {
        return a+1;
    } else {
        process_str_int(ptr, &a);
    }
    a += 1;
    return a;
}

int loops(char *ptr, int a) {
    int i = 0;
    for (; i < a; ) {
        process_str_int(ptr, &i);
        i++;
    }

    for (int ii; ii < a; ii++) {
        process_str_int(ptr, &ii);
    }

    int j = 5;
    while (j) {
        process_str_int(ptr, &j);
        j--;
    }

    int k = 0;
    do {
        process_str_int(ptr, &k);
        k++;
    } while (k);

    return a;
}
