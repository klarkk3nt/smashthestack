#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    int  pad = 0xbabe;
    char buf[1024];
    strncpy(buf, argv[1], sizeof(buf) - 1);

    printf(buf);
 
    return 0;
}
