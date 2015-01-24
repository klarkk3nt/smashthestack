Open up /levels/level01 binary in gdb:
```
$ gdb /levels/level01
```

To save yourself some trouble, set the disassembly flavor to intel:
```
(gdb) set disassembly-flavor intel
```

Disassemble the main function:
```
(gdb) disas main
Dump of assembler code for function main:
  0x08048080 <+0>:   push   0x8049128
  0x08048085 <+5>:   call   0x804810f <puts>
  0x0804808a <+10>:  call   0x804809f <fscanf>
  0x0804808f <+15>:  cmp    eax,0x10f
  0x08048094 <+20>:  je     0x80480dc <YouWin>
  0x0804809a <+26>:  call   0x8048103 <exit>
End of assembler dump.
```

You'll see in the disassembly at 0x0804808f that there is a compare to see if eax is equal to 0x10f (271). This is the 3 character key to enter to solve level1.
```
level1@io:~$ /levels/./level01
Enter the 3 digit passcode to enter: 271
Congrats you found it, now read the password for level2 from /home/level2/.pass
sh-4.2$ cat /home/level2/.pass
[This is where the password for level2 would be, but you need to solve it to get it :)]
```
