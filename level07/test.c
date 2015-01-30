#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv) {
    int count = atoi(argv[1]);

    printf("%i\n", count*sizeof(int));
    printf("%x\n", count*sizeof(int));

    return 0;
}
